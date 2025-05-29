#include <random>
__attribute__((noinline))
int foo(int *x) {
    return *x;
}
int main(int argc, char* argv[]) {
    int secret = 0;
    int i = foo(&secret);
    int gas = 100;
    while (gas > 0) {
        gas--;
        if (random() % 2 == 0) {
            secret++;
            i = foo(&secret);
        } else {
            secret--;
        }
    }
    return i;
}
