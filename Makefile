NAME 		= woody_woodpacker

CFLAG		=  -Wall -Wextra -Werror -g

SRC_C		= main.c \
		  ft_memmove.c \
		  ft_memcpy.c \
		  ft_memset.c \
		  ft_strcmp.c \
		  handle_elf64.c \
		  map_to_file.c

SRC_ASM		= rc4.asm

HEADER		= ./woodpacker.h

SRC_DIR_C  	= ./src_c/
SRC_DIR_ASM	= ./src_asm/
OBJ_DIR_C	= ./obj_c/
OBJ_DIR_ASM	= ./obj_asm/

OBJ_C		= $(addprefix $(OBJ_DIR_C), $(SRC_C:%.c=%.o))

OBJ_ASM		= $(addprefix $(OBJ_DIR_ASM), $(SRC_ASM:%.asm=%.o))

$(OBJ_DIR_ASM)%.o : $(SRC_DIR_ASM)%.asm $(HEADER)
	@mkdir -p $(OBJ_DIR_ASM)
	nasm -felf64 $< -o $@

$(OBJ_DIR_C)%.o : $(SRC_DIR_C)%.c $(HEADER)
	@mkdir -p $(OBJ_DIR_C)
	gcc -Wall -Wextra -Werror -c $< -o $@

all: $(NAME) 

$(NAME): $(OBJ_C) $(OBJ_ASM) $(HEADER)
	gcc $(CFLAGS) $(OBJ_C) $(OBJ_ASM) -o $(NAME)

clean:
		rm -rf $(OBJ_C) $(OBJ_ASM)
	
fclean: clean
		rm -rf $(NAME)

re: fclean all
