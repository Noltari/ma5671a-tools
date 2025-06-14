# ma5671a tools

This repository contains tools for the Huawei MA5671a.

## sfp-eeprom-info

### Show EEPROM1

```
python sfp-eeprom-info.py -i examples/sfp_a2_info.txt
```

### Modify EEPROM1

```
python sfp-eeprom-info.py -i examples/sfp_a2_info.txt \
	--gpon-equipment-id=123H \
	--gpon-ploam=0x11223344556677889900 \
	--gpon-serial=HWTC12345678 \
	--gpon-vendor-id=HWTC \
	--mac-address=11:22:33:44:55:66 \
	--output sfp-a2-out.txt
```
