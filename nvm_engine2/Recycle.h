#ifndef TAIR_CONTEST_RECYCLE_H
#define TAIR_CONTEST_RECYCLE_H

#include "Config.hpp"
#include "util.h"

class Recycle {
public:
    void init() {
        // 16M * 4B = 64MB
        int recycle_total = 16 * 1024 * 1024;
        int *base = (int *) malloc(recycle_total * sizeof(int));
        memset(recycles_len, 0, sizeof(int) * BIT_INTERVAL);

        int recycel_rest = recycle_total;
        for (int i = 448; i <= 944; i += 16) { // 32
            recycles_len[i] = recycle_total*0.05/32;
        }
        recycel_rest -= (static_cast<int>(recycle_total*0.05/32) *4);

        for (int i = 192; i <= 432; i += 16) { // 16
            recycles_len[i] = recycle_total*0.15/16; 
        }
        recycel_rest -= (static_cast<int>(recycle_total*0.15/16) *4);

        for (int i = 64; i <= 176; i += 16) {  // 8
            recycles_len[i] = recycle_total*0.25/8;
        }
        recycel_rest -= (static_cast<int>(recycle_total*0.25/8) *4);

        for (int i = 0; i <= 48; i += 16) {   // 4
            recycles_len[i] = recycel_rest/4;
        }

        int *offset = base;
        for (int i = 0; i < BIT_INTERVAL; i++) {
            if (recycles_len[i] > 0) {
                recycles[i] = offset;
                offset += recycles_len[i];
            }
        }
        memset(recycle_pos, 0, BIT_INTERVAL * sizeof(int));
    }

    long Get(int pos) {
        if (recycle_pos[pos] == 0) {
            return 0;
        }
        return real_offset(recycles[pos][--recycle_pos[pos]]);
    }

    bool Set(int pos, int node_offset) {
        if (recycle_pos[pos] < recycles_len[pos]) {
            recycles[pos][recycle_pos[pos]++] = node_offset;
            count++;
            return true;
        }
        return false;
    }
    // 80 ~ 1024
    int recycle_pos[BIT_INTERVAL];
    int recycles_len[BIT_INTERVAL];
    int *recycles[BIT_INTERVAL];
    int count = 0;
};


#endif //TAIR_CONTEST_RECYCLE_H