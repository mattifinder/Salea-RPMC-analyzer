
# RPMC parser

This high level analyzer parses the supplementary RPMC SPI commands, defined in JESD260. 

## Usage

Set the op1 and op2 opcode as defined in the datasheet of your SPI flash chip.
The standard recommends 0x9b (155) for op1 and 0x96 (150) for op2, when in doubt try these first.
  