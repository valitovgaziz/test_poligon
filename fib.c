#include "heads.h"  // Включаем свой заголовочный файл

// Рекурсивная реализация
int fib_recursive(int n) {
    if (n <= 1)
        return n;
    return fib_recursive(n-1) + fib_recursive(n-2);
}

// Итеративная реализация (для примера)
int fib_iterative(int n) {
    int a = 0, b = 1, c, i;
    
    if (n == 0)
        return a;
    
    for (i = 2; i <= n; i++) {
        c = a + b;
        a = b;
        b = c;
    }
    return b;
}