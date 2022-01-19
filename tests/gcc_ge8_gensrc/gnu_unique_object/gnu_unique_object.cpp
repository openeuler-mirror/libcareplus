#include <iostream>

class StudentManage
{
public:
    void setStudent(int id, int age)
    {
        student.stu_id = id;
        student.stu_age = age;
    }
    void displayStudent()
    {
        std::cout << "student " << student.stu_id << " age : " << student.stu_age << std::endl;
    }

private:
    struct Student
    {
        int stu_id;
        int stu_age;
    };

    inline static thread_local Student student;
};


int main()
{
    StudentManage ms;
    ms.setStudent(9581, 40);
    ms.displayStudent();
    ms.setStudent(9587, 36);
    ms.displayStudent();
    return 0;
}
