/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 *	 AUTHOR: Gabriel Doyle-Finch                                     *
 *     FILE: jpgdig.c                                                *
 * OVERVIEW: A forensic recovery program that identifies & restores  *
 *			 JPEG files from a corrupted CompactFlash (CF) card      *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
 
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


// Size of read/write block in bytes.
#define BLOCK_SIZE 			512

// Size of the JPEG signature in bytes.
#define SIG_SIZE 			3

// Fourth byte parameters.
#define FOURTH_BYTE_MIN		0xe0
#define FOURTH_BYTE_MAX		0xef

// Maximum number of writable files.
#define NUM_FILE_MAX		999

// Help flags.
#define HELP_FLAG_BRIEF		"-h"
#define HELP_FLAG_VERBOSE	"--help"

// Additional exit code(s).
#define EXIT_HELP_NEEDED	2

// Required command line argument count.
#define REQ_ARG_COUNT		2

// Command line argument index values.
#define CF_CARD_FILE_INDEX	REQ_ARG_COUNT - 1

// Check the given buffer for a valid JPEG signature.
bool sigcheck(const uint8_t* buf, const int buf_size); 

int main(int argc, char* argv[])
{
	// Ensure proper usage.
	if (argc != REQ_ARG_COUNT || !strcmp(argv[CF_CARD_FILE_INDEX], HELP_FLAG_BRIEF) || !strcmp(argv[CF_CARD_FILE_INDEX], HELP_FLAG_VERBOSE))
	{
		fprintf(stderr, "Usage: ./jpgdig <CF card filename>\n\n\t%s, %s\tPrint this menu & exit\n", HELP_FLAG_BRIEF, HELP_FLAG_VERBOSE);
		exit(EXIT_HELP_NEEDED);
	}
	
    // Open & error-check the forensic image file.
    FILE* img_fp;
    if (!(img_fp = fopen(argv[CF_CARD_FILE_INDEX], "r"))) 
    {
        fprintf(stderr, "Error: Could not open %s, file not found\n", argv[CF_CARD_FILE_INDEX]);
        exit(EXIT_FAILURE);
    }
    
    // Memory block used for reading & writing image data.
    uint8_t* buffer = malloc(sizeof(uint8_t) * BLOCK_SIZE);
    
    // Amount of memory chunks successfully read into the buffer.
    int chunks_read;
    
    // File pointer for recovered JPEGs.
    FILE* jpg_fp = NULL;
    
    // File number.
    unsigned int nfile = 0;
    
    while ((chunks_read = fread(buffer, sizeof(uint8_t), BLOCK_SIZE, img_fp))) 
    {
        // Check for a signature.
        if (sigcheck(buffer, chunks_read) && nfile <= NUM_FILE_MAX) 
        {
            // Close previous file if it exists.
            if (jpg_fp != NULL)
            {
                fclose(jpg_fp);
            }
            
            // Temporary storage for filenames.
            char filename[8] = { [7] = '\0' };
            
            // Initialise new filename.
            sprintf(filename, "%03d.jpg", nfile++);
    		
            // Open & error-check new file.
            if (!(jpg_fp = fopen(filename, "w"))) 
            {
                fprintf(stderr, "Error: Could not create %s\n", filename);
                fclose(img_fp);
                free(buffer);
                exit(EXIT_FAILURE);
            }
        }
        else if (nfile > NUM_FILE_MAX) 
        {
            fprintf(stderr, "Error: Max number of files reached\n");
            fclose(img_fp);
            fclose(jpg_fp);
            free(buffer);
            exit(EXIT_FAILURE);
        }
    	
        // Write image data to file.
        if (jpg_fp != NULL)
        {
            fwrite(buffer, sizeof(uint8_t), chunks_read, jpg_fp);
        }
    }
    
    // Close files & free heap memory.
    if (jpg_fp != NULL)
    {
        fclose(jpg_fp);
    }
    fclose(img_fp);
    free(buffer);
    
    // Terminate program.
    exit(EXIT_SUCCESS);
}

/**
 *  Check a given buffer for a valid JPEG signature.
 *  Returns true if valid signature, else returns false.
 */
bool sigcheck(const uint8_t* buf, const int buf_size)
{
    // Array containing the standard JPEG signature.
    const uint8_t jpg_sig[SIG_SIZE] = { 0xff, 0xd8, 0xff };
	
    // Index variable.
    int i;
	
    // Check for valid signature.
    for (i = 0; i < SIG_SIZE && i < buf_size; i++)
    {
        if (*(buf + i) != jpg_sig[i])
        {
            return false;
        }
    }
			
    // Check for valid fourth byte.
    if (*(buf + i) < FOURTH_BYTE_MIN || *(buf + i) > FOURTH_BYTE_MAX)
    {
        return false;
    }

    return true;
}