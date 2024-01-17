//Neelu: For parsing the elf of Tyche and loading it into memory.

#include <sbi/sbi_elf.h> 
#include <sbi/sbi_console.h>
//#include <assert.h>

//#define N_DBG_PRINTS

//Neelu: Make sure to update this if num_ph > 10. 
#define MAX_ELF_SEGMENTS 10

char zero[4096] = {0};

uintptr_t parse_and_load_elf(void* elf_start_addr, void* load_addr)
{

	Elf64_Ehdr* elf_header = (Elf64_Ehdr*) elf_start_addr;

#ifdef N_DBG_PRINTS
	sbi_printf("\n%s start: elf_start_addr: %p magic number: %s\n", __func__, elf_start_addr, elf_header->e_ident);	
#endif

	//Sanity check: The magic number should be as expected. 
	//assert(elf_header->e_ident == "464c457f");

#ifdef N_DBG_PRINTS
        sbi_printf("\n%s ELF HEADER FIELDS : e_entry: %llx, e_phoff: %llx \n", __func__, elf_header->e_entry, elf_header->e_phoff);
#endif

	void* ph_start = (void*) (elf_start_addr + elf_header->e_phoff);
	int num_ph = elf_header->e_phnum;
	//Neelu: Expecting 5 to be the upper bound for now. Update if num_ph > 5. 
	Elf64_Phdr program_headers[MAX_ELF_SEGMENTS];

#ifdef N_DBG_PRINTS
        sbi_printf("\n%s ELF HEADER FIELDS : ph_start: %p, num_ph: %d \n", __func__, ph_start, num_ph);
#endif

	/*
_Static_assert(
        MAX_ELF_SEGMENTS >= num_ph,
	"CAUSE: Number of program headers/segments is greater than supported number of segments. ACTION: Increase the supported number of segments if needed. ");

	assert(MAX_ELF_SEGMENTS >= num_ph);
*/

	for(int i=0; i<num_ph; i++)
	{
		program_headers[i] = *(Elf64_Phdr*)ph_start;
#ifdef N_DBG_PRINTS
		sbi_printf("\n%s PROGRAM HEADER FIELDS : type: %d PhysAddr: %llx MemSiz: %llx \n", __func__, program_headers[i].p_type, program_headers[i].p_paddr, program_headers[i].p_memsz);
#endif
		ph_start += sizeof(Elf64_Phdr);
	}


	//return 0x801013e2; 

	//Before loading the segments - find the size of the program's memory footprint, and zero it out. 
	uint64_t program_memsz = 0, prog_start_paddr = 0, last_seg_start_addr = 0, last_load_seg_memsz = 0;
	for(int i=0; i < num_ph; i++)
	{
		if(program_headers[i].p_type == PT_LOAD)
		{
			if(prog_start_paddr == 0)
			{
				prog_start_paddr = program_headers[i].p_paddr;
				last_seg_start_addr = program_headers[i].p_paddr;
#ifdef N_DBG_PRINTS
                		sbi_printf("\n%s PROGRAM START ADDR: %llx \n", __func__, program_headers[i].p_paddr);
#endif
			}
			else
			{
				program_memsz += program_headers[i].p_paddr - last_seg_start_addr;
			}
			last_load_seg_memsz = program_headers[i].p_memsz;
		}
	}
	program_memsz += last_load_seg_memsz;
#ifdef N_DBG_PRINTS
        sbi_printf("\n%s PROGRAM MEMSZ: %lx \n", __func__, program_memsz);
#endif

	//return 0x801013e2;

	//uint64_t tyche_entry = (uint64_t)load_addr + (elf_header->e_entry - prog_start_paddr);

	uint64_t tyche_entry = elf_header->e_entry;

	uint64_t zeroed_bytes = 0;
	uint64_t bytes_to_zero = program_memsz;
	//assert(bytes_to_zero > 0);
	
	while(zeroed_bytes != bytes_to_zero)
	{
		//copying from char arr with val {0} of size 4096, hence the loop.
		//assert(zeroed_bytes < bytes_to_zero);
		if(4096 > (bytes_to_zero - zeroed_bytes))
		{
			//sbi_memcpy(load_addr + zeroed_bytes, zero, (bytes_to_zero - zeroed_bytes));
			zeroed_bytes += (bytes_to_zero - zeroed_bytes);
		}
		else
		{
			//sbi_memcpy(load_addr + zeroed_bytes, zero, 4096);
			zeroed_bytes += 4096;
		}
	}

	//Finally load the segments 
	//NOTE: Deliberately ignoring the stack header for now. TODO: Need to allocate stack.
	//Only load PT_LOAD segments. 
	
	//For return val
	//uintptr_t tyche_entry = 0; 
	void* curr_seg_start_addr = 0; 

	for(int i=0; i<num_ph; i++)
	{
		if(program_headers[i].p_type != PT_LOAD)
			continue;

		//p_type == PT_LOAD

		//assert(program_headers[i].p_align >= 0x1000);
		//assert(program_headers[i].p_memsz >= program_headers[i].p_filesz);
		
		//copy the memory region
		//The source needs to be computed using p_offset. But need to ensure that load_addr is computed appropriately (difference between PhysAddr for both segments). 
		curr_seg_start_addr = load_addr + (program_headers[i].p_paddr - prog_start_paddr); 
		//check if execute flag is set, should be the entry point. 
                //if(program_headers[i].p_flags & PF_X)
                //        tyche_entry = (uintptr_t) curr_seg_start_addr;
#ifdef N_DBG_PRINTS
                sbi_printf("\n%s curr_seg_start_addr %p \n", __func__, curr_seg_start_addr);
#endif
		sbi_memcpy(curr_seg_start_addr, (program_headers[i].p_offset+elf_start_addr), program_headers[i].p_filesz);

		/*
		load_addr += program_headers[i].p_filesz; 

		if(program_headers[i].p_memsz > program_headers[i].p_filesz)
		{
			uint64_t zeroed_bytes = 0; 
			uint64_t bytes_to_zero = (program_headers[i].p_memsz - program_headers[i].p_filesz);
			//assert(bytes_to_zero > 0);
#ifdef N_DBG_PRINTS
                	sbi_printf("\n%s Zeroing memory region - to expand program segment. \n", __func__);
#endif
			while(zeroed_bytes != bytes_to_zero)
			{
				//copying from char arr with val {0} of size 4096, hence the loop. 
				//assert(zeroed_bytes < bytes_to_zero);
				if(4096 > (bytes_to_zero - zeroed_bytes))
				{
					sbi_memcpy(load_addr, zero, (bytes_to_zero - zeroed_bytes));
					load_addr += (bytes_to_zero - zeroed_bytes);
					zeroed_bytes += (bytes_to_zero - zeroed_bytes);
				}
				else
				{
					sbi_memcpy(load_addr, zero, 4096);
					load_addr += 4096; 
					zeroed_bytes += 4096;
				}
			}				
		}

		//Zeroing bytes for expanding the segment (to ensure offset between segments w.r.t. paddr). 
		if(i < num_ph-1)
		{
			if((uint64_t)(load_addr - curr_seg_start_addr) < (program_headers[i+1].p_paddr - program_headers[i].p_paddr))
			{
				//TODO: Should I zero the mem? 
				uint64_t zeroed_bytes = 0;
                        	uint64_t bytes_to_zero = ((program_headers[i+1].p_paddr - program_headers[i].p_paddr) - (uint64_t)(load_addr - curr_seg_start_addr));

#ifdef N_DBG_PRINTS
                        	sbi_printf("\n%s Zeroing memory region - to expand program segment. \n", __func__);
#endif

				while(zeroed_bytes != bytes_to_zero)
				{
					//copying from char arr with val {0} of size 4096, hence the loop.
					//assert(zeroed_bytes < bytes_to_zero);
					if(4096 > (bytes_to_zero - zeroed_bytes))
					{
						sbi_memcpy(load_addr, zero, (bytes_to_zero - zeroed_bytes));
						load_addr += (bytes_to_zero - zeroed_bytes);
						zeroed_bytes += (bytes_to_zero - zeroed_bytes);
					}
					else
					{
						sbi_memcpy(load_addr, zero, 4096);
						load_addr += 4096;
						zeroed_bytes += 4096;
					}
                        	}
				//load_addr += ((program_headers[i+1].p_paddr - program_headers[i].p_paddr) - (load_addr - curr_seg_start_addr))	
			}

		}*/
	}

//#ifdef N_DBG_PRINTS
        sbi_printf("\n%s tyche_entry %lx \n", __func__, tyche_entry);
//#endif

	//return 0x801013e2;

	return tyche_entry; 

	//TODO: Allocate Stack! 

}



