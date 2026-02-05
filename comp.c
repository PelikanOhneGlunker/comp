#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

typedef struct HashType {
	int len; 
	const char *name;
} HashType;

HashType types[] = {
    {128, "sha512sumbyte"},
    {64, "sha256sumbyte"},
    {32, "md5byte"}
};

typedef struct MemNode {
    void *ptr;
    struct MemNode *next;
} MemNode;

static int len_types = 0;
static MemNode *mem_head = NULL;
#define NR_OF_ELEMNTS 12

void printHashTypes();
int getLen(char *s1, char *s2);
int getLength(char *str);
bool compare(char *s1, char *s2, int length);
void pri(uint64_t col, char *text);
void expandString(uint8_t nrOfChars, char c);
void drawLine(uint8_t len);
void drawBreaks(uint8_t len);
int char_to_int(char ca, char cb);
char* getHashByIndex(int index);
int memlist_add(void *ptr);
char* getZeroLine();
void memlist_free_all();

int main(int argc, char **argv) {
    char *s1 = NULL;
    char *s2 = NULL;
    if (argc == 1) {
        goto show_help;
    }
    if (argc == 2) {
        goto length;
    }
    if (argc == 3) {
        if (argv[1][0] == 'i' && argv[1][1] == 'n' && argv[1][2] == '=') {
	    goto cmp_to_stored_hash;
        }
    }
    if (argc == 3) {
        s1 = argv[1];
        s2 = argv[2];
        goto calcu;
    }

length:
    printf("Length: %d\n", getLength(argv[1]));
    return 0;

show_help:
    printf("@VERSION 2.3\n");
    printf("params <string> <string>\n");
    printf("params <in=index> <string>\n");
    printHashTypes();
    return 0;
 
cmp_to_stored_hash:
    int index = 0;
    if (strlen(argv[1]) == 4) {
        index = char_to_int(argv[1][3], '\0');
    } else {
        index = char_to_int(argv[1][3], argv[1][4]);
    }
    s1 = getHashByIndex(index);
    s2 = argv[2];
    goto calcu;

calcu:
    printf("%s\n", s1);
    printf("%s\n", s2);
    int length = getLen(s1, s2);
    if (length < 0) {
        return -1;
    }
    drawBreaks(1);
    drawLine(length);
    drawBreaks(1);
    for (int i = 0; i < len_types; ++i) {
        if (types[i].len == length) {
	    pri(0xAAAAFF, "Checksum Type: ");
	    pri(0xAAAAFF, (char*) types[i].name);
	    drawBreaks(1);
	}
    }
    if (compare(s1, s2, length)) {
        pri(0xFF33FF, "Strings are same\n");
    } else {
    	pri(0xFF0000, "Strings are not same\n");
    }
    if (mem_head != NULL) {
        memlist_free_all();
    }
    return 0;
}

int char_to_int(char ca, char cb) {
    if (cb == '\0') {
    	const char numb[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    	for (int i = 0; i < 10; ++i) {
            if (numb[i] == ca) {
            	return i;
            }
        }
    } else {
        int a = char_to_int(ca, '\0');
	int b = char_to_int(cb, '\0');
	int index = (a * 10) + b;
	if (index >= NR_OF_ELEMNTS) {
	    return -1;
	}
	return index;
    }
    return -1;
}

bool compare(char *s1, char *s2, int length) {
   for (int i = 0; i < length; ++i, ++s1, ++s2) {
        if (*s1 != *s2) {
            return false;
        }
    }
    return true;
}

void printHashTypes() {
    for (int i = 0; i < len_types; ++i) {
        printf("%s: %d chars\n", types[i].name, types[i].len);
    }
}

int getLength(char *str) {
    int counter = 0;
    while (*str != '\0' && counter < 88888) {
    	if (counter == 88888) {
	    pri(0xFF0000000044, "ERROR: 88888");
	}
	++str;
	++counter;
    }
    return counter;
}

int getLen(char *s1, char *s2) {
    char *ptr_s1 = s1;
    char *ptr_s2 = s2;
    int len_s1 = 0;
    int len_s2 = 0;
    while (*s1 != '\0') {
        ++s1;
	++len_s1;
    }
    while (*s2 != '\0') {
        ++s2;
        ++len_s2;
    }
    if (len_s1 != len_s2) {
        printf("Size not same: s1: %d, s2: %d\n", len_s1, len_s2);
	return -1;
    } else {
    	return len_s1;
    }
}

void pri(uint64_t col, char *ptext) {
    uint8_t bg_r = (col >> 40) & 0xFF;// vordergrundfarben
    uint8_t bg_g = (col >> 32) & 0xFF;
    uint8_t bg_b = (col >> 24) & 0xFF;
    uint8_t fg_r = (col >> 16) & 0xFF;// hintergrundfarben
    uint8_t fg_g = (col >> 8)  & 0xFF;
    uint8_t fg_b = col         & 0xFF;
    printf("\033[38;2;%d;%d;%dm", fg_r, fg_g, fg_b);
    printf("\033[48;2;%d;%d;%dm", bg_r, bg_g, bg_b);
    printf("%s", ptext);
    printf("\033[0m");
}

void drawLine(uint8_t len) {
    expandString(len, '-');
}

void drawBreaks(uint8_t len) {
    expandString(len, '\n');
}

void expandString(uint8_t nrOfChars, char c) {
    char *ptr = malloc((nrOfChars + 1) * sizeof(char));
    char *start = ptr;
    for (uint8_t i = 0; i < nrOfChars; ++i) {
        *ptr = c;
        ++ptr;
    }
    *ptr = '\0';
    ptr = start;
    pri(0xFFFFFF, ptr);
    free(ptr);
}

int memlist_add(void *ptr) {
    if (!ptr) return -1;
    MemNode *n = malloc(sizeof(MemNode));
    if (!n) return -1;
    n->ptr = ptr;
    n->next = mem_head;
    mem_head = n;
    return 0;
}

void memlist_free_all() {
    MemNode *cur = mem_head;
    while (cur) {
        MemNode *next = cur->next;
        if (cur->ptr) free(cur->ptr);
        free(cur);
        cur = next;
    }
    mem_head = NULL;
}

char* getHashByIndex(int index) {
    if (index < 0 || index >= NR_OF_ELEMNTS) {
        return getZeroLine();
    }
    char **list = malloc(NR_OF_ELEMNTS * sizeof(char *));
    if (!list) return NULL;
    if (!(index < NR_OF_ELEMNTS)) return NULL;
    for (int i = 0; i < NR_OF_ELEMNTS; ++i) {
        list[i] = malloc(65);
        memlist_add(list[i]);
    }
    memlist_add(list);
    strncpy(list[0], "cba495d5531b9ae618aebfa61a7eb3a134dd362230b0edc5c4e5bd015aa22b72", 65);
    strncpy(list[1], "0ab73a04f7ec03145cbe59db74bcd5d772173909c6062277ea980b66e5e7d5ed", 65);
    strncpy(list[2], "5bccdf3125cdaa619af16694111632f5bb7a4969ef34829ee7df483defeec253", 65);
    strncpy(list[3], "8421c2381126e310865645bc696a7223dca987115c2802d230fb6a27171c51ec", 65);
    strncpy(list[4], "bff6e72e6213696a61ce93273d16699b1d494c3b0ce9ab4474fcb9920be80c4c", 65);
    strncpy(list[5], "c37e4d235f92f1678f4d97f1d9093c7a3498305a06e1f204a1f61e88409342f7", 65);
    strncpy(list[6], "374b11dd325ababbc96e7e41bf71848548cb0c3cc883b5dbf2802ec99234d7b4", 65);
    strncpy(list[7], "0f7526b7366091a4af04576f070c7e154e42d130770ce6fe04d151dfd6b8749f", 65);
    strncpy(list[8], "e890f942a664474ca3e8e217590905e3ad3dac420217bab0d248629c00593290", 65);
    strncpy(list[9], "4bbb9e26d0cf0d4b40009dd400425d098eddf3f23543846f838cfa72475a58ca", 65);
    strncpy(list[10], "abb2fabcac26f3f9dad8cb92068558729a7c82a1177e6df29f8b6ae2771ef2fd", 65);
    strncpy(list[11], "7d1d4e4234ff184e427a831151971668affd2f24d856e95c3e1e73d0c895f55c", 65);
    return list[index];
}

char* getZeroLine() {
    static const char MYZERO[] = "0000000000000000000000000000000000000000000000000000000000000000";
    char *buf = malloc(65);
    strncpy(buf, MYZERO, 65);
    return buf;
}

