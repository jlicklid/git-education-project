// rewrite queen
// joel licklider
//
#ifndef queen_h
#define queen_h
// queen class definition
class Queen
{
public:
    Queen(int, Queen *);

    bool findSolution();
    bool advance();
    void print();

private:
    int row;
    const int column;
    Queen * neighbor;

    bool canAttack (int, int);
};
#endif
