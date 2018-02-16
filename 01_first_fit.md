# How2Heap Study 01 First Fit

## Tech Overview

Demonstrating glibc malloc's first-fit behavior.

## Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	fprintf(stderr, "This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.\n");
	fprintf(stderr, "glibc uses a first-fit algorithm to select a free chunk.\n");
	fprintf(stderr, "If a chunk is free and large enough, malloc will select this chunk.\n");
	fprintf(stderr, "This can be exploited in a use-after-free situation.\n");

	fprintf(stderr, "Allocating 2 buffers. They can be large, don't have to be fastbin.\n");
	char* a = malloc(512);
	char* b = malloc(256);
	char* c;

	fprintf(stderr, "1st malloc(512): %p\n", a);
	fprintf(stderr, "2nd malloc(256): %p\n", b);
	fprintf(stderr, "we could continue mallocing here...\n");
	fprintf(stderr, "now let's put a string at a that we can read later \"this is A!\"\n");
	strcpy(a, "this is A!");
	fprintf(stderr, "first allocation %p points to %s\n", a, a);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "We don't need to free anything again. As long as we allocate less than 512, it will end up at %p\n", a);

	fprintf(stderr, "So, let's allocate 500 bytes\n");
	c = malloc(500);
	fprintf(stderr, "3rd malloc(500): %p\n", c);
	fprintf(stderr, "And put a different string here, \"this is C!\"\n");
	strcpy(c, "this is C!");
	fprintf(stderr, "3rd allocation %p points to %s\n", c, c);
	fprintf(stderr, "first allocation %p points to %s\n", a, a);
	fprintf(stderr, "If we reuse the first allocation, it now holds the data from the third allocation.");
}
```

## Output

```
This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.
glibc uses a first-fit algorithm to select a free chunk.
If a chunk is free and large enough, malloc will select this chunk.
This can be exploited in a use-after-free situation.
Allocating 2 buffers. They can be large, don't have to be fastbin.
1st malloc(512): 0x2531010
2nd malloc(256): 0x2531220
we could continue mallocing here...
now let's put a string at a that we can read later "this is A!"
first allocation 0x2531010 points to this is A!
Freeing the first one...
We don't need to free anything again. As long as we allocate less than 512, it will end up at 0x2531010
So, let's allocate 500 bytes
3rd malloc(500): 0x2531010
And put a different string here, "this is C!"
3rd allocation 0x2531010 points to this is C!
first allocation 0x2531010 points to this is C!
If we reuse the first allocation, it now holds the data from the third allocation.
```

## 개요 번역

Demonstrating glibc malloc's first-fit behavior.

`glibc`가 사용하는 `First-Fit` 메모리 배치 알고리즘 동작에 대해 알아본다.

## 출력 번역

(일부는 추가 코멘트를 넣었다.)

```
This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.
이 파일은 공격을 위한 파일이 아니다. 그러나, glibc의 메모리 할당자의 동작을 보여준다.

glibc uses a first-fit algorithm to select a free chunk.
glibc 는 해제되었던 메모리 공간을 선택하는데 First-Fit (최초 적합) 알고리즘을 사용한다.

If a chunk is free and large enough, malloc will select this chunk.
만약 어떠한 한 청크가 해제되어 있고 충분히 크다면, malloc는 이 청크를 선택한다.

This can be exploited in a use-after-free situation.
이것은 use-after-free 공격이 가능한 상황을 만든다.

Allocating 2 buffers. They can be large, don't have to be fastbin.
2개의 버퍼를 할당하였다. 이들의 크기는 커질 수 있으며, 항상 fastbin 일 필요는 없다.

1st malloc(512): 0x2531010
2nd malloc(256): 0x2531220

we could continue mallocing here...
우리는 여기서 계속 할당을 할 수 있다.

now let's put a string at a that we can read later "this is A!"
이제 나중에 읽을 수 있도록 "this is A!" 라는 문자열을 넣는다.

first allocation 0x2531010 points to this is A!
첫 번째로 할당한 0x2531010 지점의 값은 this is A! 이다.

Freeing the first one...
첫 번째로 할당한 메모리를 해제한다.

We don't need to free anything again. As long as we allocate less than 512, it will end up at 0x2531010
우리는 더이상 메모리를 해제할 필요가 없다. 이제 우리가 512 보다 더 작은 크기의 메모리를 할당한다면, 이것은 0x2531010 지점에 위치할 것이다.

So, let's allocate 500 bytes
이제, 500 바이트만큼 메모리를 할당한다.

3rd malloc(500): 0x2531010

And put a different string here, "this is C!"
그리고 이곳에 다른 문자열 this is C! 를 넣는다.

3rd allocation 0x2531010 points to this is C!
세 번째로 할당한 0x2531010 지점의 값은 this is C! 이다.

first allocation 0x2531010 points to this is C!
첫 번째로 할당했던 0x2531010 지점의 값도 this is C! 이다.

If we reuse the first allocation, it now holds the data from the third allocation.
만약 우리가 첫 번째로 할당했던 곳을 재사용하게 된다면, 이것은 세 번째로 할당했던 공간의 값들을 그대로 사용하게 된다.
```