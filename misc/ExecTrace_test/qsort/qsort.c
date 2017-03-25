#include<stdio.h>
#include<stdlib.h>
#include<string.h>
 
#define BUF_LEN 50

void swap(int* a, int* b)
{
    int t = *a;
    *a = *b;
    *b = t;
}

int partition (int arr[], int low, int high)
{
    int pivot = arr[high];
    int i = (low - 1);
 
    for (int j = low; j <= high- 1; j++)
    {
        if (arr[j] <= pivot)
        {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }
    swap(&arr[i + 1], &arr[high]);
    return (i + 1);
}
 
void quickSort(int arr[], int low, int high)
{
    if (low < high)
    {
        int pi = partition(arr, low, high);
 
        quickSort(arr, low, pi - 1);
        quickSort(arr, pi + 1, high);
    }
}
 
int main(int argc, char **argv)
{
    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
	return 0;
    }

    char buf[BUF_LEN];
    if (fgets(buf, BUF_LEN, file) != NULL) {
	/* get number of elements in the array. */
	char *num = strtok(buf, ": ");
	int arr[atoi(num)];

	/* get input. */
	int i = 0;
	while (num) {
	    arr[i++] = atoi(num);
	    num = strtok(NULL, " ");
	}
	int n = sizeof(arr)/sizeof(arr[0]);
	quickSort(arr, 0, n-1);

	/* print result. */
	for (i = 0; i < n; i++) {
	    printf("%d ", arr[i]);
	}
	printf("\n");
    }
    return 0;
}
