#include <string.h> 
#include <sys/shm.h> 
#include <sys/types.h> 
#include <sys/mman.h> 
#include <sys/file.h> 
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32; 
 
#ifdef __x86_64__
typedef unsigned long long u64;
#else
typedef uint64_t u64;
#endif /* ^__x86_64__ */

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;
    
 
#define MAP_SIZE            (1 << 21)
#define ROL32(_x, _r)  ((((u32)(_x)) << (_r)) | (((u32)(_x)) >> (32 - (_r))))
#define ROL64(_x, _r)  ((((u64)(_x)) << (_r)) | (((u64)(_x)) >> (64 - (_r))))
#define HASH_CONST          0xa5b35705
#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

static u8* trace_bits;                /* SHM with instrumentation bitmap  */
static u8 trace_bits_snap[MAP_SIZE];            

static u8 virgin_bits[MAP_SIZE];     /* Regions yet untouched by fuzzing */

//feilong：添加virgin_bits_maintain，保存的最近一次队列为空时的virgin_bits
static u8 virgin_bits_maintain[MAP_SIZE];
//feilogn:添加iteration_maintain,保存的最近一次队列为空时的iteration
static int iteration_maintain;

static u8 session_virgin_bits[MAP_SIZE];     /* Regions yet untouched while the SUT is still running */

static const u8 count_class_lookup8[256] = { 
  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128 
};

static u16 count_class_lookup16[65536];


void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) 
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] = 
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];

}

u32 count_branch() {
  
  u8* mem = virgin_bits;

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return (MAP_SIZE << 3) - ret;

}

#ifdef __x86_64__

static inline void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];

    }

    mem++;

  }

}

#else

void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];

    }

    mem++;

  }

}

#endif /* ^__x86_64__ */


int init()
{
    char* shm_str = getenv("SHM_ENV_VAR");
    if(shm_str)
    {

      s32 shm_id = open(shm_str, O_RDWR); 
      if(shm_id < 0)
      {
        return 0;
      }
      trace_bits = (u8*)mmap(NULL, MAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, shm_id, 0);  
      close(shm_id);  

      memset(virgin_bits, 255, MAP_SIZE); 
      init_count_class16();
      return 1;
    }
    return 0;
}

// u8* copy(char* mem)
// {
//     char* first_trace;
//     memcpy(first_trace, mem, MAP_SIZE);
//     return first_trace;
// }

void clear_trace_bits()
{   
    // memset(mem, 0, sizeof(mem));
    memset(trace_bits, 0, MAP_SIZE); 
}

// void* mmaloc()
// { 
//   void* virgin_bits = malloc(MAP_SIZE); 
//   memset(virgin_bits, 255, MAP_SIZE); 
//   return virgin_bits;
// }
 
u32 hash32(const void* key, u32 len, u32 seed) {

  const u64* data = (u64*)key;
  u64 h1 = seed ^ len;

  len >>= 3;

  while (len--) {

    u64 k1 = *data++;

    k1 *= 0x87c37b91114253d5ULL;
    k1  = ROL64(k1, 31);
    k1 *= 0x4cf5ad432745937fULL;

    h1 ^= k1;
    h1  = ROL64(h1, 27);
    h1  = h1 * 5 + 0x52dce729;

  }

  h1 ^= h1 >> 33;
  h1 *= 0xff51afd7ed558ccdULL;
  h1 ^= h1 >> 33;
  h1 *= 0xc4ceb9fe1a85ec53ULL;
  h1 ^= h1 >> 33;

  return h1;

}

u32 hash_after_classify() {

    memcpy(trace_bits_snap, trace_bits, MAP_SIZE);

#ifdef __x86_64__
    classify_counts((u64*)trace_bits_snap);
#else
    classify_counts((u32*)trace_bits_snap);
#endif /* ^__x86_64__ */

    return hash32(trace_bits_snap, MAP_SIZE, HASH_CONST);

}

u8 has_new_bits(u8* virgin_map, u8* trace_bit) {

#ifdef __x86_64__

  u64* current = (u64*)trace_bit;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

#else
  u32* current = (u32*)trace_bit;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

  u8   ret = 0;

  while (i--) { 

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin)) { 

      if (likely(ret < 2)) { 

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;  

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef __x86_64__ 

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1; 

#else 

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1; 

#endif /* ^__x86_64__ */ 
      } 

      *virgin &= ~*current; 

    } 

    current++;
    virgin++; 

  }  
  return ret; 
} 

void termination_detection_init()
{
    memset(session_virgin_bits, 255, MAP_SIZE);
}

int termination_detection()
{
    return has_new_bits(session_virgin_bits, trace_bits);
}

int newPath()
{ 
     
/*
    printf("trace_bits = ");
    
    for (int i = 0; i < MAP_SIZE; ++i)
        {
          if (trace_bits[i] != 0)
            printf("no 0 %d", i); 
        }
    printf("\n");
*/
#ifdef __x86_64__
    classify_counts((u64*)trace_bits);
#else
    classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

    u8 hnb = has_new_bits(virgin_bits, trace_bits);

    printf("hnb = %d\n", hnb);
    if (hnb != 0)
    {
        printf("new path found !!!\n");
        return hnb;
    } 
    else
    {
        printf("opps! No path found !!!\n");
        return 0;
    }
            
}

//feilong:添加virgin_bit和iteration相关函数
//feilong：添加内存内更新最近一次virgin_bit和iteration的函数
int feilong_update(int iteration){
    printf("feilong:feilong_update start\n");
    memcpy(virgin_bits_maintain,virgin_bits,MAP_SIZE);
    iteration_maintain=iteration;
    printf("feilong:feilong_update end\n");
    return 0;
}

//feilong:添加crash时保存到文件系统函数
int feilong_save(char * path){
    //feilong：保存iteartion和virgin_bit到文件系统中
    //如果没创建path上的路径，创建
    FILE *fp= fopen(path,"wb");
    if(fp==NULL){
        printf("feilong:feilong_save function fopen error!\n");
        return 1;
    }
    //写入iteration_maintain
    if(1 != fwrite(&iteration_maintain,sizeof(iteration_maintain),1,fp)){
        printf("feilong:feilong_save function writes error iteration!\n");
        return 1;
    }
    //写入virgin_bit
    int return_byte_num = fwrite(virgin_bits_maintain,1,MAP_SIZE,fp);
    if(return_byte_num != MAP_SIZE){
        printf("feilong:feilong_save function writes error virgin_bit!\n");
        return 1;
    }
    //关闭文件写流
    fclose(fp);
    return 0;
}

//feilong:添加读取函数
int feilong_read(char *path,int * iteration){
    //打开文件
    FILE * fp = fopen(path,"rb");
    if(fp==NULL){
        printf("feilong:feilong_read function cannot open the virgin file!\n");
        return 1;
    }
    //读取iteration_maintain
    if(1 != fread(iteration,sizeof(iteration_maintain),1,fp)){
        printf("feilong:feilong_read function reads error iteration!\n");
        return 1;
    }
    //读取virgin_bit
    if(MAP_SIZE != fread(virgin_bits,1,MAP_SIZE,fp)){
        printf("feilong:feilong_read function reads error virgin_bit!\n");
        return 1;
    }
    fclose(fp);
    return 0;
}
