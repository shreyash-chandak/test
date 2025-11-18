#include "ss_write_helpers.h"
#include "ss_file_ops.h" // For send_ss_error
#include "ss_structs.h"
#include "utils.h"
#include "common.h"
#include <errno.h>    // For errno, ENOENT
#include <ctype.h>    // For isspace
#include <sys/stat.h> // For stat
#include <dirent.h>   // For opendir

/**
 * @brief Reads a single sentence (ending in . ! ?) from a file.
 */
char* read_sentence(FILE* fp, int* delim) {
    size_t size = 128;
    char* buffer = malloc(size);
    if (!buffer) return NULL;

    int c;
    size_t i = 0;
    while ((c = fgetc(fp)) != EOF) {
        if (i >= size - 1) {
            size *= 2;
            char* new_buffer = realloc(buffer, size);
            if (!new_buffer) { free(buffer); return NULL; }
            buffer = new_buffer;
        }
        buffer[i++] = (char)c;
        if (c == '.' || c == '!' || c == '?') {*delim = 1; break;}
    }
    buffer[i] = '\0';
    if (i == 0) { free(buffer); return NULL; }
    
    char* start = buffer;
    while(isspace(*start)) start++;
    if(strlen(start) == 0) { free(buffer); return NULL; }
    if (start != buffer) memmove(buffer, start, strlen(start) + 1);
    return buffer;
}

uint32_t get_sentence_count(StorageServerState* state, const char* filename) {
    char file_path[MAX_PATH_LEN];
    snprintf(file_path, MAX_PATH_LEN, "%s/%s", state->data_dir, filename);
    
    FILE* fp = fopen(file_path, "r");
    if (!fp) {
        return 0; // File doesn't exist, so 0 sentences
    }
    
    int delim = 0;
    uint32_t count = 0;
    char* sentence = read_sentence(fp,&delim);
    while (sentence != NULL && delim) {
        count++;
        free(sentence);
        delim = 0;
        sentence = read_sentence(fp,&delim);
    }
    if (sentence != NULL) free(sentence);

    fclose(fp);
    return count;
}

/**
 * @brief Helper to apply a *single* WriteOp to a sentence.
 * Returns a new, malloc'd string with the result.
 */
char* apply_single_op(const char* original_sentence, WriteOp* op) {
    // --- 1. Tokenize the original sentence ---
    char* sentence_copy = strdup(original_sentence);
    char delimiter[2] = {0}; // To store the final '.', '!', or '?'
    char* suffix = NULL;
    
    char* delim_ptr = strpbrk(sentence_copy, ".!?");
    if (delim_ptr) {
        delimiter[0] = *delim_ptr; // Save the delimiter
        *delim_ptr = '\0';         // Cut the sentence
        suffix = delim_ptr + 1;
    }

    char* words[MAX_BUFFER_LEN]; 
    size_t word_count = 0;
    char* token = strtok(sentence_copy, " ");
    while(token && word_count < MAX_BUFFER_LEN) {
        if (strlen(token) > 0) {
            words[word_count++] = token;
        }
        token = strtok(NULL, " ");
    }

    // --- 2. Build the new word list by merging ---
    // We need +1 for the new word, and +1 for safety
    char* new_words[MAX_BUFFER_LEN + 2];
    size_t new_word_count = 0;
    size_t word_idx = 0;
    bool op_inserted = false;

    // Loop until we've placed all original words AND the new op
    while (word_idx < word_count || !op_inserted) {
        
        // If this is the correct index, insert the new content
        if (!op_inserted && word_idx == op->word_index) {
            new_words[new_word_count++] = op->content;
            op_inserted = true;
            // NOTE: We DO NOT increment word_idx. This is an insert.
        }
        
        // If there are original words left, add the next one
        else if (word_idx < word_count) {
            new_words[new_word_count++] = words[word_idx];
            word_idx++;
        } 
        // If we're at the end and still haven't inserted, append the op
        else if (!op_inserted) {
            new_words[new_word_count++] = op->content;
            op_inserted = true;
        }
    }
    
    // --- 3. Concatenate the new word list into a final string ---
    // (This allocation is an estimate, but should be safe)
    char* new_sentence = malloc(strlen(original_sentence) + MAX_WRITE_CONTENT_LEN + 128); 
    new_sentence[0] = '\0';
    
    for(size_t i = 0; i < new_word_count; i++) {
        strcat(new_sentence, new_words[i]);
        if (i < new_word_count-1) {
            strcat(new_sentence, " ");
        }
    }
    
    // --- 4. Add the delimiter back *if* it existed ---
    if (delimiter[0] != 0) {
        strcat(new_sentence, delimiter);
    }

    // Add the suffix back (The remaining sentences) 
    if (suffix != NULL) strcat(new_sentence, suffix);

    free(sentence_copy);
    return new_sentence;
}

/**
 * @brief Applies the list of WriteOps to a single sentence string.
 */
char* apply_ops_to_sentence(const char* original_sentence, WriteOp* ops_list) {
    
    // --- 1. Put all ops into a temporary array ---
    size_t op_count = 0;
    WriteOp* op = ops_list;
    while(op) { op_count++; op = op->next; }

    if (op_count == 0) {
        return strdup(original_sentence); // No changes
    }
    
    WriteOp** op_array = malloc(sizeof(WriteOp*) * op_count);
    op = ops_list;
    for(size_t i = 0; i < op_count; i++) {
        op_array[i] = op;
        op = op->next;
    }
    
    // --- 2. Initialize the sentence state ---
    char* current_sentence = strdup(original_sentence);

    // --- 3. Apply ops IN REVERSE ARRAY ORDER (which is FIFO) ---
    // The ops_list is a LIFO stack (new ops are prepended).
    // The array is also in LIFO order.
    // We must iterate the array backwards to get the FIFO order 
    // specified by the project doc.
    
    for (int i = (int)op_count - 1; i >= 0; i--) {
        WriteOp* current_op = op_array[i];
        
        // Apply the op to the *current* state
        char* next_sentence = apply_single_op(current_sentence, current_op);
        
        // Free the intermediate state
        free(current_sentence);
        
        // The result becomes the new current state for the next loop
        current_sentence = next_sentence;
    }

    // --- 4. Cleanup and return ---
    free(op_array); // Free the temp array (not the ops themselves)
    
    // current_sentence now holds the final, correct result
    return current_sentence;
}

/**
 * @brief This is the *REAL* file-merge logic.
 */
int apply_changes_to_file(StorageServerState* state, WriteSession* session, const char* tmp_path, const char* final_path) {
    FILE* in = fopen(tmp_path, "r");
    FILE* out = fopen(final_path, "w");
    
    if (!out) {
        safe_printf("SS: apply_changes: Could not open final file for writing.\n");
        if (in) fclose(in);
        return -1;
    }
    
    // Handle new file creation (no backup)
    if (!in) {
        safe_printf("SS: apply_changes: No backup, creating new file.\n");
        if (session->sentence_index != 0) {
            safe_printf("SS: apply_changes: Error: Index %u out of bounds for new file.\n", session->sentence_index);
            fclose(out);
            return -1; // Error
        }
        // This is a new file, just apply ops to an empty string
        char* new_sentence = apply_ops_to_sentence("", session->operations);
        fputs(new_sentence, out);
        free(new_sentence);
        fclose(out);
        return 0; // Success
    }

    safe_printf("SS: apply_changes: Merging file...\n");
    char* sentence;
    uint32_t current_sentence_index = 0;
    int result = 0, delim_local = 0;
    bool op_applied = false; 

    while ((sentence = read_sentence(in, &delim_local)) != NULL) {
        if (current_sentence_index == session->sentence_index) {
            safe_printf("SS: apply_changes: Modifying sentence %u\n", current_sentence_index);
            char* new_sentence = apply_ops_to_sentence(sentence, session->operations);
            fputs(new_sentence, out);
            free(new_sentence);
            op_applied = true; 
        } else {
            // This sentence is not being edited, write it as-is
            fputs(sentence, out);
        }
        free(sentence); // Free the buffer from read_sentence
        
        // Add a space between sentences if we're not at the end
        int next_char = fgetc(in);
        if (next_char != EOF) {
            ungetc(next_char, in); // Put it back
            fputc(' ', out);
        }
        current_sentence_index++;
    }
    
    // Handle append:
    // If we did NOT apply an op AND the index is the end of the file
    if (!op_applied && session->sentence_index == current_sentence_index) {
        safe_printf("SS: apply_changes: Appending new sentence %u\n", current_sentence_index);
        char* new_sentence = apply_ops_to_sentence("", session->operations);
        if (current_sentence_index > 0) fputs(" ", out);
        fputs(new_sentence, out);
        free(new_sentence);
        op_applied = true; // Mark as applied
    }
    // Handle error:
    // If we finished and never applied the op (and it wasn't an append), the index was invalid.
    else if (!op_applied) {
        safe_printf("SS: apply_changes: Error: Sentence index %u out of bounds (%u)\n",
            session->sentence_index, current_sentence_index);
        result = -1; // This will fail the ETIRW
    }

    fclose(in);
    fclose(out);
    return result;
}
