#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <execinfo.h>
#include <time.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/syscall.h>

#include "libgotoku.h"

#define GAMEPFX "GOTOKU: "

__attribute__((constructor)) static void
__libinit()
{
	fprintf(stderr, GAMEPFX "library loaded (%d, %d).\n", getuid(), getgid());
	return;
}

static int _initialized = 0;
static void *__stored_ptr = NULL;
static gotoku_t *_board;

void game_set_ptr(void *ptr)
{
	_initialized = 1;
	__stored_ptr = ptr;
}

void *
game_get_ptr()
{
	return __stored_ptr;
}

int game_init()
{
	fprintf(stderr, GAMEPFX "library init - stored pointer = %p.\n", __stored_ptr);
	return 0;
}

gotoku_t *
game_load(const char *fn)
{
	gotoku_t *gt = NULL;
	FILE *fp = NULL;
	int i, j, k;
	if ((fp = fopen(fn, "rt")) == NULL)
	{
		fprintf(stderr, GAMEPFX "fopen failed - %s.\n", strerror(errno));
		return NULL;
	}
	if ((gt = _board = (gotoku_t *)malloc(sizeof(gotoku_t))) == NULL)
	{
		fprintf(stderr, GAMEPFX "alloc failed - %s.\n", strerror(errno));
		goto err_quit;
	}
	gt->x = gt->y = 0;
	for (i = 0; i < 9; i++)
	{
		for (j = 0; j < 9; j++)
		{
			if (fscanf(fp, "%d", &k) != 1)
			{
				fprintf(stderr, GAMEPFX "load number (%d, %d) failed - %s.\n", j, i, strerror(errno));
				goto err_quit;
			}
			gt->board[i][j] = k;
		}
	}
	fclose(fp);
	fprintf(stderr, GAMEPFX "game loaded\n");
	return gt;
err_quit:
	if (gt)
		free(gt);
	if (fp)
		fclose(fp);
	_board = NULL;
	return NULL;
}

static int
cmpint(const void *a, const void *b)
{
	int pa = *((int *)a);
	int pb = *((int *)b);
	return pa > pb;
}

static int
game_check_internal(int numbers[9])
{
	int i;
	qsort(numbers, 9, sizeof(int), cmpint);
	for (i = 0; i < 9; i++)
	{
		if (numbers[i] != i + 1)
			return -1;
	}
	return 0;
}

int game_check()
{
	gotoku_t *gt = _board;
	int i, j, numbers[9];
	// check each row
	for (i = 0; i < 9; i++)
	{
		for (j = 0; j < 9; j++)
		{
			numbers[j] = gt->board[i][j];
		}
		if (game_check_internal(numbers) < 0)
			return -1;
	}
	// check each column
	for (i = 0; i < 9; i++)
	{
		for (j = 0; j < 9; j++)
		{
			numbers[j] = gt->board[j][i];
		}
		if (game_check_internal(numbers) < 0)
			return -1;
	}
	// check each block
	for (i = 0; i < 9; i += 3)
	{
		for (j = 0; j < 9; j += 3)
		{
			int p, q;
			for (p = 0; p < 3; p++)
			{
				for (q = 0; q < 3; q++)
				{
					numbers[p * 3 + q] = gt->board[i + p][j + q];
				}
			}
			if (game_check_internal(numbers) < 0)
				return -1;
		}
	}
	// state: OK
	printf("Bingo!\n");
	return 0;
}

void game_free(gotoku_t *gt)
{
	_board = NULL;
	free(gt);
}

static int _dirx[] = {0, 0, -1, 1};
static int _diry[] = {-1, 1, 0, 0};

static void
gop_move(int d)
{
	gotoku_t *gt = _board;
	int nx = (gt->x + _dirx[d] + 9) % 9;
	int ny = (gt->y + _diry[d] + 9) % 9;
	//
	gt->x = nx;
	gt->y = ny;
}

void gop_show()
{
	int i, j;
	gotoku_t *gt = _board;
	printf("%d %d\n", gt->x, gt->y);
	for (i = 0; i < 9; i++)
	{
		for (j = 0; j < 9; j++)
		{
			char sep = (j != 8 ? ' ' : '\n');
			printf("%d%c", gt->board[i][j], sep);
		}
	}
}

void gop_up() { gop_move(0); }
void gop_down() { gop_move(1); }
void gop_left() { gop_move(2); }
void gop_right() { gop_move(3); }
void gop_random() { gop_move(rand() % 4); }

static void
gop_fill(int n)
{
	gotoku_t *gt = _board;
	gt->board[gt->y][gt->x] = n;
}

void gop_fill_0() { gop_fill(0); }
void gop_fill_1() { gop_fill(1); }
void gop_fill_2() { gop_fill(2); }
void gop_fill_3() { gop_fill(3); }
void gop_fill_4() { gop_fill(4); }
void gop_fill_5() { gop_fill(5); }
void gop_fill_6() { gop_fill(6); }
void gop_fill_7() { gop_fill(7); }
void gop_fill_8() { gop_fill(8); }
void gop_fill_9() { gop_fill(9); }

#define GAME_OP(n) \
	void gop_##n() { gop_random(); }
#include "gops.c"
#undef GAME_OP

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define SIZE 9

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
