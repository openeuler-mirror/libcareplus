#include <iostream>

class CTest
{
public:
    CTest():m_i2(1) {}
    void print()
    {
        int sum = m_i1+m_i2;
        std::cout << "sum is " << sum << std::endl;

        int sub = m_i1-m_i2;
        std::cout << "sub is " << sub << std::endl;
    }
private:
    static int m_i1;
    int m_i2;
};

int CTest::m_i1 = 10;

int main()
{
    CTest ct1;
    ct1.print();

    return 0;
}
