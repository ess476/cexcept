
with open('syscall.list') as f:
    calls = list(f)

calls = [x.split('.')[0] for x in calls]

f = open("sys_defines.h","w+")

f.write("#pragma once\n\n");

for call in calls:

	if len(call) == 0:
		continue

	#f.write("#ifdef {}\n".format(call))
	f.write("#define {}(...)\t except_sys({}(__VA_ARGS__))\n\n".format(call, call))
	#f.write("#endif\n\n");

f.close();
