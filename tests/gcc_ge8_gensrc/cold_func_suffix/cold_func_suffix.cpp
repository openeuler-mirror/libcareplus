#include <iostream>

extern int ext_func(int a, int b) __attribute__((cold));

void swap(int &a, int &b)
{
    int temp = a;
    a = b;
    b = temp;
}

int cold_func(int a, int b)
{
    int c = 0;
    if(__builtin_expect(a > 0, false))
        c = a*2 + b;
    else
        c = ext_func(a, b) + 7;

    return c;
}

void reverse(int &a)
{
    int org = a;
    int res = 0;
    while(org > 0)
    {
        res *= 10;
        res += org % 10;
        org /= 10;
    }
    a = res;
}

int main()
{
    int i = 9527;
    int m = i/9;
    int n = i%9;

    int k = cold_func(m, n);
    swap(m, n);
    reverse(i);

    std::cout << "k=" << k << " i=" << i << std::endl;
    return 0;
}
