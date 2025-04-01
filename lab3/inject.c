#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include "libgotoku.h"
#include <dlfcn.h>
#define GAMEPFX "GOTOKU: "
#define SIZE 9
#define MAIN_OFFSET 0x16c89
#define SERVER
#ifdef SERVER
#include "got_offset_server.c"
#else
#include "got_offset_local.c"
#endif
static void *__stored_ptr = NULL;
int *getSolvedBoard(int *board, int index);
bool check(int *board, int index);
void *createHanle();
bool solve(int *board, int index);
void modifyEntry(void *handle, char *method, int gotCount);
void completeBoard(int *board, int *solvedBoard, void *handle);
void *realMainAddress;

int game_init()
{
    gotoku_t *board = NULL;
    gotoku_t copyBoard;
    fprintf(stderr, GAMEPFX "library init - stored pointer = %p.\n", __stored_ptr);
    printf("UP113_GOT_PUZZLE_CHALLENGE\n");
    printf("SOLVER: _main = %p\n", game_get_ptr());
    board = game_load("/gotoku.txt");
    copyBoard = *board;
    int *solvedBoard = getSolvedBoard((int *)copyBoard.board, 0);
    realMainAddress = game_get_ptr();
    // modify GOT table entry to achieve the solved sudoku
    // offset is fixed, so simply (real address - main address + offset)
    void *handle = createHanle();
    completeBoard((int *)board->board, solvedBoard, handle);
    return 0;
}

void modifyEntry(void *handle, char *method, int gotCount)
{
    void (*gop)(void) = (void (*)(void))dlsym(handle, method);
    void *got = realMainAddress - MAIN_OFFSET + GOT_OFFSET[gotCount];
#ifdef SERVER
    uintptr_t page_start = (uintptr_t)got & ~(getpagesize() - 1);
    // 讓 GOT 變成可寫
    if (mprotect((void *)page_start, getpagesize(), PROT_READ | PROT_WRITE) != 0)
    {
        perror("mprotect");
        exit(EXIT_FAILURE);
    }
#endif
    void **got_entry = (void **)got;
    *got_entry = (void *)gop;
#ifdef SERVER
    // 還原 GOT 權限（只讀）
    if (mprotect((void *)page_start, getpagesize(), PROT_READ) != 0)
    {
        perror("mprotect restore");
        exit(EXIT_FAILURE);
    }
#endif
}

void completeBoard(int *board, int *solvedBoard, void *handle)
{
    int gotCount = 0;
    for (int i = 0; i < 9; i++)
    {
        for (int j = 0; j < 9; j++)
        {
            int index = i * SIZE + j;
            if (board[index] != solvedBoard[index])
            {
                switch (solvedBoard[index])
                {
                case 1:
                    modifyEntry(handle, "gop_fill_1", gotCount++);
                    break;
                case 2:
                    modifyEntry(handle, "gop_fill_2", gotCount++);
                    break;
                case 3:
                    modifyEntry(handle, "gop_fill_3", gotCount++);
                    break;
                case 4:
                    modifyEntry(handle, "gop_fill_4", gotCount++);
                    break;
                case 5:
                    modifyEntry(handle, "gop_fill_5", gotCount++);
                    break;
                case 6:
                    modifyEntry(handle, "gop_fill_6", gotCount++);
                    break;
                case 7:
                    modifyEntry(handle, "gop_fill_7", gotCount++);
                    break;
                case 8:
                    modifyEntry(handle, "gop_fill_8", gotCount++);
                    break;
                case 9:
                    modifyEntry(handle, "gop_fill_9", gotCount++);
                    break;
                default:
                    break;
                }
            }
            modifyEntry(handle, "gop_right", gotCount++);
        }
        // change position to next row start
        for (int i = 0; i < 9; i++)
        {
            modifyEntry(handle, "gop_left", gotCount++);
        }
        modifyEntry(handle, "gop_down", gotCount++);
    }
}

void *createHanle()
{
    void *handle;
    int (*game_init)(void);
    char *error;
    const char *lib = "libgotoku.so";
    handle = dlopen(lib, RTLD_LAZY);
    if (!handle)
    {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    dlerror(); /* Clear any existing error */
    return handle;
}

bool check(int *board, int index)
{
    int ans = board[index];
    int row = index / SIZE;
    int col = index % SIZE;

    // Check row
    for (int i = 0; i < SIZE; i++)
    {
        if ((row * SIZE + i != index) && board[row * SIZE + i] == ans)
        {
            return false;
        }
    }

    // Check column
    for (int i = 0; i < SIZE; i++)
    {
        if ((i * SIZE + col != index) && board[i * SIZE + col] == ans)
        {
            return false;
        }
    }

    // Check 3x3 sub-grid
    int startRow = (row / 3) * 3;
    int startCol = (col / 3) * 3;
    for (int i = 0; i < 3; i++)
    {
        for (int j = 0; j < 3; j++)
        {
            int blkIndex = (startRow + i) * SIZE + (startCol + j);
            if (blkIndex != index && board[blkIndex] == ans)
            {
                return false;
            }
        }
    }

    return true;
}

int *getSolvedBoard(int *board, int index)
{
    solve(board, 0);
    return board;
}

bool solve(int *board, int index)
{
    if (index >= SIZE * SIZE)
        return true;
    if (board[index] != 0)
    {
        return solve(board, index + 1);
    }

    for (int guess = 1; guess <= SIZE; guess++)
    {
        board[index] = guess;
        if (check(board, index) && solve(board, index + 1))
        {
            return true;
        }
    }

    board[index] = 0;
    return false;
}
