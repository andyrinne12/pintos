/*
 * 17.14 format (fixed-format) utils:
 */

#ifndef PINTOS_15_FIXED_POINT_H
#define PINTOS_15_FIXED_POINT_H

#define SHIFT (1 << 14)
#define ROUND (SHIFT / 2)

/*
 * Conversion utils:
 */
#define INT_TO_FIXED(n) ((n) * SHIFT)
#define FIXED_TO_INT(x) ((x) / SHIFT)
#define FIXED_TO_INT_ROUNDED(x) ((x) >= 0) ? (((x) + ROUND) / SHIFT) : (((x) - ROUND) / SHIFT)

/*
 * Operations between two fixed-point numbers:
 */
#define ADD_FIXED_FIXED(x, y) ((x) + (y))
#define SUB_FIXED_FIXED(x, y) ((x) - (y))
#define MUL_FIXED_FIXED(x, y) ((((int64_t) x) * (y)) / SHIFT)
#define DIV_FIXED_FIXED(x, y) (((int64_t) x) * (SHIFT)) / (y)

/*
 * Operations between fixed-point number and integer:
 */
#define ADD_FIXED_INT(x, n) ((x) + (n) * SHIFT)
#define SUB_FIXED_INT(x, n) ((x) - (n) * SHIFT)
#define MUL_FIXED_INT(x, n) ((x) * (n))
#define DIV_FIXED_INT(x, n) ((x) / (n))

#endif //PINTOS_15_FIXED_POINT_H

