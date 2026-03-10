#include <stdio.h>
#include <stddef.h>
#include "heads.h"

int main()
{
    printf("NULL = %p\n", (void *)NULL); // Output: NULL = 0000000000000000

    int a = 10;
    int fib_rec, fib_iter;
    fib_rec = fib_recursive(a);
    fib_iter = fib_iterative(a);

    printf("Fibonachi (recursive) = %d\n", fib_rec);
    printf("Fibonachi (iterative) = %d\n", fib_iter);

    return 0;
}
