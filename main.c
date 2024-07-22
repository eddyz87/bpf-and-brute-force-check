#include <stdio.h>
#include <stdint.h>

typedef  int8_t s8;
typedef uint8_t u8;

typedef  int32_t s32;
typedef uint32_t u32;

/* 6-bit signed integers */
#define MIN ((s8)0xe0)
#define MAX ((s8)0x1f)

/* /\* 4-bit signed integers *\/ */
/* #define MIN ((s8)0xf8) */
/* #define MAX ((s8)0x07) */

/*
 * #define MIN INT8_MIN
 * #define MAX INT8_MAX
 */

struct bpf_reg_state {
	s8 smin_value;
	s8 smax_value;
};

static inline s8 min(s8 a, s8 b) { return a > b ? b : a; }
static inline s8 max(s8 a, s8 b) { return a > b ? a : b; }

#define ASM_INPUT_RM "r"
/**
 * fls - find last set bit in word
 * @x: the word to search
 *
 * This is defined in a similar way as the libc and compiler builtin
 * ffs, but returns the position of the most significant set bit.
 *
 * fls(value) returns 0 if value is 0 or the position of the last
 * set bit if value is nonzero. The last (most significant) bit is
 * at position 32.
 */
static __always_inline int fls(unsigned int x)
{
	int r;

	if (__builtin_constant_p(x))
		return x ? 32 - __builtin_clz(x) : 0;

	/*
	 * AMD64 says BSRL won't clobber the dest reg if x==0; Intel64 says the
	 * dest reg is undefined if x==0, but their CPU architect says its
	 * value is written to set it to the same as before, except that the
	 * top 32 bits will be cleared.
	 *
	 * We cannot do this on 32 bits because at the very least some
	 * 486 CPUs did not behave this way.
	 */
	asm("bsrl %1,%0"
	    : "=r" (r)
	    : ASM_INPUT_RM (x), "0" (-1));
	return r + 1;
}


static inline s32 negative_bit_floor(s32 v)
{
	u8 bits = fls(~v); /* find most-significant unset bit */
	u32 delta;

	/* special case, needed because 1UL << 32 is undefined */
	if (bits > 31)
		return 0;

	delta = (1UL << bits) - 1;
	return ~delta;
}


static void scalar_min_max_and(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	/* Rough estimate tuned for [-1, 0] & -CONSTANT cases. */
	dst_reg->smin_value = negative_bit_floor(min(dst_reg->smin_value,
						     src_reg->smin_value));
	dst_reg->smax_value = max(dst_reg->smax_value, src_reg->smax_value);
}

/*
 * /\* stolen: https://stackoverflow.com/a/19885112 *\/
 * static void print_byte(uint8_t byte)
 * {
 * 	static const char *bit_rep[16] = {
 * 		[ 0] = "0000", [ 1] = "0001", [ 2] = "0010", [ 3] = "0011",
 * 		[ 4] = "0100", [ 5] = "0101", [ 6] = "0110", [ 7] = "0111",
 * 		[ 8] = "1000", [ 9] = "1001", [10] = "1010", [11] = "1011",
 * 		[12] = "1100", [13] = "1101", [14] = "1110", [15] = "1111",
 * 	};
 * 	printf("%s%s", bit_rep[byte >> 4], bit_rep[byte & 0x0F]);
 * }
 */

/* static int abs(int a) */
/* { */
/* 	return a > 0 ? a : -a; */
/* } */

struct stats {
	uint64_t samples;
	double total_delta_min;
	double total_delta_max;
};

static int check_one(s8 a, s8 b, s8 c, s8 d, struct stats *stats)
{
	struct bpf_reg_state dst = { a, b };
	struct bpf_reg_state src = { c, d };
	int ok = 1;

	s8 true_min = a & c;
	s8 true_max = a & c;
        for (s8 i = a; i <= b; ++i) {
		for (s8 j = c; j <= d; ++j) {
			true_min = min(true_min, i & j);
			true_max = max(true_max, i & j);
		}
	}

	scalar_min_max_and(&dst, &src);
	if (dst.smin_value > true_min) {
		printf("constraint violation (%d, %d), (%d, %d): dst.smin_value=%d, true_min=%d\n",
		       a, b, c, d, dst.smin_value, true_min);
		ok = 0;
	}
	if (dst.smax_value < true_max) {
		printf("constraint violation (%d, %d), (%d, %d): dst.smax_value=%d, true_max=%d\n",
		       a, b, c, d, dst.smax_value, true_max);
		ok = 0;
	}
	if (dst.smax_value < dst.smin_value) {
		printf("constraint violation (%d, %d), (%d, %d): dst.smin_value=%d, dst.smax_value=%d\n",
		       a, b, c, d, dst.smin_value, dst.smax_value);
		ok = 0;
	}
	/* stats->samples++; */
	/* double delta_min = abs(true_min - (int)dst.smin_value)/(double)(MAX-MIN); */
	/* double delta_max = abs(true_max - (int)dst.smax_value)/(double)(MAX-MIN); */
	/* stats->total_delta_min += delta_min; */
	/* stats->total_delta_max += delta_max; */
	/* if (delta_min > 0.1 || delta_max > 0.1) */
	/* 	printf("%2d,%2d,%2d,%2d,%2d,%2d\n", a, b, c, d, */
	/* 	       abs(true_min - (int)dst.smin_value), abs(true_max - (int)dst.smax_value)); */
	return ok;
}

int main(int argc, char *argv[])
{
	struct stats stats = {};
	const int cnt_max = 10;
	int cnt = 0;

        for (s8 a = MIN; a <= MAX; ++a)
		for (s8 b = a; b <= MAX; ++b)
			for (s8 c = MIN; c <= MAX; ++c)
				for (s8 d = c; d <= MAX && cnt < cnt_max; ++d)
					cnt += check_one(a, b, c, d, &stats) ? 0 : 1;
	if (cnt == cnt_max)
		printf("  ...\n");
	printf("done, %s\n", cnt == 0 ? "ok" : "failed");
	/* printf("Avg. delta min: %5.2f\n", stats.total_delta_min / (double)stats.samples); */
	/* printf("Avg. delta max: %5.2f\n", stats.total_delta_max / (double)stats.samples); */
	return 0;
}
