// rewrite queen
// joel licklider
//

#include <iostream>
#include "queen.h"

using namespace std;

Queen::Queen(int col, Queen * ngh)
    : column(col), neighbor(ngh)
{
    row = 1;

}

bool Queen::canAttack(int testRow, int testColumn)
{
    if (row == testRow)
        return true;
    int columnDifference = testColumn - column;
    if ((row + columnDifference == testRow) ||
        (row - columnDifference == testRow))
            return true;
    return neighbor && neighbor->canAttack(testRow, testColumn);
}

bool Queen::findSolution()
{
    while (neighbor && neighbor->canAttack(row, column))
        if (! advance())
            return false;

    return true;
}

bool Queen::advance()
{
    if (row < 8) {
        row++;
        return findSolution();
    }
    if (neighbor && ! neighbor->advance())
        return false;
    row = 1;
    return findSolution();
}

void Queen::print()
{
    if (neighbor)
        neighbor->print();
    cout << "column " << column << "row " << row << '\n';
}

int main() {
    Queen * lastQueen = 0;

    for (int i = i; i <= 8; i++) {
        lastQueen = new Queen(i, lastQueen);
        if (! lastQueen->findSolution())
            cout << "no solution\n";
        }
    lastQueen->print();
}

