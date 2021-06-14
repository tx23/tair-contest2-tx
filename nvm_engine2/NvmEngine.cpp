#include "NvmEngine.hpp"
#include <libpmem.h>
#include <thread>
#include "Recycle.h"
#include "MurmurHash2.hpp"
#include "crc32.hpp"

static char __ch[1024];

int abs_diff(int a, int b)
{
    int c = a - b;
    if (c < 0)
    {
        return -c;
    }
    else
        return c;
}

Status DB::CreateOrOpen(const std::string &name, DB **dbptr, FILE *log_file)
{
    g_log_file = log_file;
    return NvmEngine::CreateOrOpen(name, dbptr);
}

DB::~DB() {}

Status NvmEngine::CreateOrOpen(const std::string &name, DB **dbptr)
{
    NvmEngine *db = new NvmEngine(name);
    *dbptr = db;
    return Ok;
}

void NvmEngine::_preHeat()
{
    long interval_len = 2 * 1024 * 1024L;
    long buffer_size = 64L;
    long pre_write_size = 64 * 1024 * 1024 * 1024L - buffer_size;
    char *buffer = (char *)malloc(buffer_size);
    for (long i = 0; i < pre_write_size; i += interval_len)
    {
        // pmem_memcpy_nodrain(buffer, file_data + i, buffer_size);
        // pmem_drain();
        pmem_memcpy_nodrain(file_data + i, buffer, buffer_size);
        pmem_drain();
    }
    free(buffer);
}

NvmEngine::NvmEngine(const std::string &name)
{
    if ((pmem_base = (char *)pmem_map_file(name.c_str(), PMEM_SIZE,
                                           PMEM_FILE_CREATE,
                                           0666, &_mapped_len,
                                           &_is_pmem)) == NULL)
    {
        perror("Pmem map file failed");
        exit(1);
    }
    //AEP
    file_write_offset = (long *)pmem_base;
    file_data = pmem_base;
    //索引
    hash_table = (int *)malloc(INDEX_SIZE * sizeof(int));
    memset(hash_table, 0, INDEX_SIZE * sizeof(int));
    key_node = (char *)malloc(MEM_KEY_NUM * MEM_NODE_SIZE);
    memset(key_node, 0, MEM_KEY_NUM * MEM_NODE_SIZE);

    key_counter = 1; //注意从1开始，0为结束。
    for(int i = 0; i < 16; i++)
        memset(key_counter_cnts[i], 0, sizeof(Counter) * 16);

    for (int i = 0; i < 16; ++i)
    {
        recycles[i].init();
    }
    //缓存
    // 1042 = 2(val_size) + 16(key) + 1024(value)
    t_cache = (char *)malloc(LOCK_SIZE * CACHE_BLOCK_LEN);
    memset(t_cache, 0, LOCK_SIZE * CACHE_BLOCK_LEN);

    // 初始化预写
    if (*file_write_offset != 17)
    {
        _preHeat();
        *file_write_offset = 17;
        pmem_drain();
        file_write_offset++;
    }
    else
    {
        _buildIndexAndGc();
    }
}

NvmEngine::~NvmEngine()
{
    if (g_log_file)
    {
        fclose(g_log_file);
    }

    if (t_cache)
    {
        free(t_cache);
    }

    if (hash_table)
    {
        free(hash_table);
    }

    if (key_node)
    {
        free(key_node);
    }

    pmem_unmap(pmem_base, _mapped_len);
}

static std::atomic<int> getNum(0);

Status NvmEngine::Get(const Slice &key, std::string *value)
{
    static thread_local int tid = getNum++;
    // static thread_local int get_cnt = 0;
    static thread_local bool is_first = true;

    char *suffix_key = key.data() + 3; //由于hash包含了前3字节，所以同一桶只需保留后13字节用于比较
    int hash = MurmurHash2(key.data(), 16);
    int lock_slot = hash & LOCK_MASK;

    std::lock_guard<spin_mutex> lock(*(mut_locks + lock_slot));

    char *cache_index = t_cache + lock_slot * CACHE_BLOCK_LEN;
    short value_len = *((short *)cache_index);
    char *value_offset = cache_index + 18;

    if (value_len != 0L && memcmp(cache_index + 2, key.data(), 16) == 0)
    {
        if (value->length() == 0)
        {
            *value = std::string(value_offset, value_len);
        }
        else
        {
            if (is_first)
            {
                *value = std::string(value_offset, 1024);
                is_first = false;
            }
            *((long *)((char *)value + 8)) = value_len;
            memcpy(&((*value)[0]), value_offset, value_len);
        }
        return Ok;
    }

    int key_node_pos = *(hash_table + hash);
    while (key_node_pos != 0)
    {
        // | key:13 | file_addr:4 | pre_ptr:4 | version:1 block_size:1 val_len:2 |
        char *key_node_addr = key_node + key_node_pos * MEM_NODE_SIZE;
        if (memcmp(key_node_addr, suffix_key, 13) == 0)
        {
            long addr = real_offset(*((int *)(key_node_addr + MEM_NODE_FILE_ADDR_OFFSET)));
            short val_len = *((short *)(key_node_addr + MEM_NODE_VAL_LEN_OFFSET));

            *((short *)cache_index) = val_len;
            memcpy(cache_index + 2, key.data(), 16);
            memcpy(value_offset, file_data + addr + 24, val_len);

            //|crc:2|version:1|block_size:1|val_len:2|key:16|value|
            if (value->length() == 0)
            {
                *value = std::string(value_offset, val_len);
            }
            else
            {
                if (is_first)
                {
                    *value = std::string(__ch, 1024);
                    is_first = false;
                }
                *((long *)((char *)value + 8)) = val_len;
                memcpy(&((*value)[0]), value_offset, val_len);
            }

            return Ok;
        }
        key_node_pos = *((int *)(key_node_addr + MEM_NODE_PRE_PTR_OFFSET));
    }

    return NotFound;
}

static std::atomic<long> setNum(0);

Status NvmEngine::Set(const Slice &key, const Slice &value)
{
    static thread_local int tid = setNum++;
    // static thread_local int set_cnt = 0;
    static thread_local long local_file_write_offset = 0;
    static thread_local long local_file_write_limit = 0;
    static thread_local int local_key_counter_offset = 0;
    static thread_local int local_key_counter_limit = 0;
    static thread_local Recycle recycle = recycles[tid & 15];

    // |crc:4|version:1|block_size:1|val_len:2|key:16|value|
    static thread_local char *write_buffer = (char *)malloc(24 + 1024 + 8);
    static thread_local int *crc = (int *)(write_buffer);         //4字节crc
    static thread_local char *version = write_buffer + 4;             //1字节版本号
    static thread_local char *block_size = write_buffer + 5;          //1字节块大小
    static thread_local short *val_len = (short *)(write_buffer + 6); //2字节val长度
    static thread_local char *key_store = (char *)(write_buffer + 8); //16字节key
    static thread_local char *value_buffer = write_buffer + 24;       //value

    // static thread_local int tmp_store[BIT_INTERVAL];
    // static thread_local bool init_tmp_store = false;

    *val_len = (short)value.size();
    memcpy(key_store, key.data(), 16);
    memcpy(value_buffer, value.data(), value_size);

    int value_size = *val_len;
    int write_value_size = value_size + 24;
    int align8_block_size = align8(write_value_size); //分配块长度 按照8字节对齐

    char *suffix_key = key.data() + 3; //由于hash包含了前3字节，所以同一桶只需保留后13字节用于比较
    int hash = MurmurHash2(key.data(), 16) & LOCK_MASK;

    std::lock_guard<spin_mutex> lock(*(mut_locks + hash));

    //缓存
    char *cache_index = t_cache + hash * CACHE_BLOCK_LEN;
    short value_len = *((short *)cache_index);
    if (value_len != 0L && memcmp(cache_index + 2, key.data(), 16) == 0)
    {
        *((short *)cache_index) = 0; //置缓存失效
    }
    //索引
    int *hash_table_ptr = hash_table + hash;
    int key_node_pos = *hash_table_ptr;
    while (key_node_pos != 0)
    {
        // | key:13 | file_addr:4 | pre_ptr:4 | version:1 block_size:1 val_len:2 |
        char *key_node_addr = key_node + key_node_pos * MEM_NODE_SIZE;

        if (memcmp(suffix_key, key_node_addr, 13) == 0)
        {

            char relative_block_size = *(key_node_addr + 22);           
            int old_block_size = real_offset_char(relative_block_size); //块大小是按照8字节对齐
            int pos = old_block_size - 80 - 24;                         //需要再减24才能对齐

            int *key_file_addr = (int *)(key_node_addr + MEM_NODE_FILE_ADDR_OFFSET);
            /*
            //1.原地更新
            if (old_block_size == align8_block_size)
            { 
                *version = *(key_node_addr + MEM_NODE_VERSION_OFFSET) + 1;
                *block_size = relative_block_size;
                *crc = crc32(write_buffer, write_value_size);
                tmp_file_addr
                pmem_memcpy_nodrain(file_data + real_offset(*key_file_addr), write_buffer, write_value_size);
                pmem_drain();

                *(key_node_addr + MEM_NODE_VERSION_OFFSET) = (char)(*(key_node_addr + MEM_NODE_VERSION_OFFSET) + 1); //更新version
                *((short *)(key_node_addr + MEM_NODE_VAL_LEN_OFFSET)) = (short)value_size;                           //更新value_size
                return Ok;
            }
            */


            //从aep中分配空间追加更新val
            relative_block_size = relative_offset_char(align8_block_size);
            *version = *(key_node_addr + MEM_NODE_VERSION_OFFSET) + 1;
            *block_size = relative_block_size;
            *crc = crc32(write_buffer, write_value_size);

            if (local_file_write_offset + align8_block_size > local_file_write_limit)
            {
                get_file_write_meta(local_file_write_offset, local_file_write_limit);
            }

            pmem_memcpy_nodrain(file_data + local_file_write_offset, write_buffer, write_value_size);
            pmem_drain();

            //回收
            recycle.Set(pos, *key_file_addr); //先回收

            //更新索引
            *key_file_addr = relative_offset(local_file_write_offset);                 //更新file_addr
            *(key_node_addr + MEM_NODE_BLOCK_SIZE_OFFSET) = relative_block_size;       //更新block_size
            *((short *)(key_node_addr + MEM_NODE_VAL_LEN_OFFSET)) = (short)value_size; //更新value_size

            local_file_write_offset += align8_block_size;

            return Ok;
        }
        key_node_pos = *((int *)(key_node_addr + MEM_NODE_PRE_PTR_OFFSET));
    }

    long file_write_pos = 0;
    //GC
    if (local_file_write_offset > GC_USAGE_THRESHOLD && recycle.count > 0)
    {
        // 使用回收池
        int pos = align8_block_size - 80 - 24;
        while (pos < GC_JUMP_LIMIT)
        {
            long node_offset = recycle.Get(pos);
            //可以复用
            if (node_offset > 0)
            { //从回收池取数据块
                align8_block_size = pos + 80 + 24;
                file_write_pos = node_offset;
                break;
            }
            pos += GC_JUMP_LEN;
        }
    }

    //回收池没可用空间，使用aep
    if (file_write_pos == 0)
    {
        //从aep中分配空间
        if (local_file_write_offset + align8_block_size > local_file_write_limit)
        {
            get_file_write_meta(local_file_write_offset, local_file_write_limit);
        }

        file_write_pos = local_file_write_offset;
        local_file_write_offset += align8_block_size;
    }

    char relative_block_size = relative_offset_char(align8_block_size);

    //追加写入新记录 |crc:4|version:1|block_size:1|val_len:2|key:16|value|
    *version = 1;
    *block_size = relative_block_size;
    *crc = crc32(write_buffer, write_value_size);

    pmem_memcpy_nodrain(file_data + file_write_pos, write_buffer, write_value_size);
    pmem_drain();

    if (local_key_counter_offset >= local_key_counter_limit)
    {
        local_key_counter_offset = key_counter + (tid & 15) * MEM_KEY_ALLOCATOR_SIZE + key_counter_cnts[tid & 15].cnt * 16 * MEM_KEY_ALLOCATOR_SIZE;
        key_counter_cnts[tid & 15].cnt++;
        local_key_counter_limit = local_key_counter_offset + MEM_KEY_ALLOCATOR_SIZE;
        if (local_key_counter_limit >= MEM_KEY_NUM)
        {
            return OutOfMemory;
        }
    }

    key_node_pos = local_key_counter_offset++;
    // | key:16 | file_addr:4 | pre_ptr:4 |version:1 block_size:1 val_len:2 |
    char *key_node_addr = key_node + key_node_pos * MEM_NODE_SIZE;

    //更新索引
    memcpy(key_node_addr, suffix_key, 13);                                                   // key
    *((int *)(key_node_addr + MEM_NODE_FILE_ADDR_OFFSET)) = relative_offset(file_write_pos); //file_addr
    *((int *)(key_node_addr + MEM_NODE_PRE_PTR_OFFSET)) = *hash_table_ptr;                   //pre_ptr
    *((char *)(key_node_addr + MEM_NODE_VERSION_OFFSET)) = 1;                                //version
    *((char *)(key_node_addr + MEM_NODE_BLOCK_SIZE_OFFSET)) = relative_block_size;           //block_size
    *((short *)(key_node_addr + MEM_NODE_VAL_LEN_OFFSET)) = (short)value_size;               //val_len

    *hash_table_ptr = key_node_pos;

    return Ok;
}

void NvmEngine::get_file_write_meta(long &local_file_write_offset, long &local_file_write_limit)
{
    offset_lock.lock();
    local_file_write_offset = *file_write_offset;
    local_file_write_limit = local_file_write_offset + AEP_WRITE_BUF_SIZE;
    pmem_memcpy_nodrain(file_write_offset, &local_file_write_limit, 8);
    pmem_drain();
    offset_lock.unlock();
}

//恢复重建索引
void NvmEngine::_buildIndexAndGc()
{
    // |crc:4|version:1|block_size:1|val_len:2|key:16|value|
    char *buffer = (char *)malloc(24 + 1024);
    int *crc = (int *)buffer;           // 4字节crc校验值
    char *version = buffer + 4;             //1字节版本号
    char *block_size = buffer + 5;          //1字节块大小 一块最大1048
    short *val_len = (short *)(buffer + 6); //2字节val长度
    char *key_store = (char *)(buffer + 8); //16字节key
    char *suffix_key = key_store + 3;

    long file_write_pos = *file_write_offset;

    int bit_cnts[BIT_INTERVAL];
    memset(bit_cnts, 0, sizeof(int) * BIT_INTERVAL);

    for (long i = 0; i < PMEM_SIZE; i += AEP_WRITE_BUF_SIZE)
    {
        long start = i, end = i + AEP_WRITE_BUF_SIZE;
        while (start < end)
        {
            char *addr = file_data + start;
            memcpy(buffer, addr, 24);
            if (*version <= 0)
            { //版本号不大于0跳出循环
                if (*block_size <= 0)
                {
                    break;
                }
                else
                {
                    //未使用的临时缓冲记录，可以回收
                    //gc recovery
                    int pos = *block_size - 80 - 24;
                    int tid = bit_cnts[pos]++;
                    recycles[(tid & 15)].Set(pos, relative_offset(start));

                    start += real_offset_char(*block_size);

                    continue;
                }
            }

            memcpy(buffer + 24, addr + 24, *val_len);
            if (crc32(buffer, 24 + *val_len) == *crc)
            {
                int hash = MurmurHash2(key_store, 16) % INDEX_MASK;
                bool is_new_key = true;
                int key_node_pos = hash_table[hash];
                while (key_node_pos != 0)
                {
                    // | key:16 | file_addr:4 | pre_ptr:4 | version:1 block_size:1  val_len:2 |
                    char *key_node_addr = key_node + key_node_pos * MEM_NODE_SIZE;
                    if (memcmp(key_node_addr, suffix_key, 13) == 0)
                    {
                        // |crc:4|version:1|block_size:1|val_len:2|key:16|value|
                        if (*version >= *(key_node_addr + MEM_NODE_VERSION_OFFSET))
                        {   
                            //回收旧版本记录
                            int pos = *(key_node_addr + MEM_NODE_BLOCK_SIZE_OFFSET) - 80 - 24;
                            int tid = bit_cnts[pos]++;
                            recycles[(tid & 15)].Set(pos, *((int *)(key_node_addr + MEM_NODE_FILE_ADDR_OFFSET)));
                            //更新
                            *((int *)(key_node_addr + MEM_NODE_FILE_ADDR_OFFSET)) = relative_offset(start); //file_addr
                            *(key_node_addr + MEM_NODE_VERSION_OFFSET) = *version;
                            *(key_node_addr + MEM_NODE_BLOCK_SIZE_OFFSET) = *block_size;
                            *((short *)(key_node_addr + MEM_NODE_VAL_LEN_OFFSET)) = *val_len;
                        }
                        else
                        {
                            //无效记录可以回收
                            //gc recovery
                            int pos = *block_size - 80 - 24;
                            int tid = bit_cnts[pos]++;
                            recycles[(tid & 15)].Set(pos, relative_offset(start));
                        }
                        is_new_key = false;
                        break;
                    }
                    key_node_pos = *((int *)(key_node_addr + MEM_NODE_PRE_PTR_OFFSET));
                }

                //新增
                if (is_new_key)
                {
                    key_node_pos = key_counter++;
                    // | key:13 | file_addr:4 | pre_ptr:4 | version:1 block_size:1 val_len:2 |
                    char *key_node_addr = key_node + key_node_pos * MEM_NODE_SIZE;
                    //更新内存
                    memcpy(key_node_addr, suffix_key, 13);                                          //key
                    *((int *)(key_node_addr + MEM_NODE_FILE_ADDR_OFFSET)) = relative_offset(start); //file_addr
                    *((int *)(key_node_addr + MEM_NODE_PRE_PTR_OFFSET)) = hash_table[hash];         //pre_ptr
                    *(key_node_addr + MEM_NODE_VERSION_OFFSET) = *version;
                    *(key_node_addr + MEM_NODE_BLOCK_SIZE_OFFSET) = *block_size;
                    *((short *)(key_node_addr + MEM_NODE_VAL_LEN_OFFSET)) = *val_len; //block_size、version、val_len

                    hash_table[hash] = key_node_pos;
                }
            }
            else
            {
                //损坏记录回收
                int pos = *block_size - 80 - 24;
                int tid = bit_cnts[pos]++;
                recycles[(tid & 15)].Set(pos, relative_offset(start));
            }
            start += real_offset_char(*block_size);
        }
    }

    free(buffer);
}
