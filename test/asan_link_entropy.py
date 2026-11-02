Import("env")
env.Append(LINKFLAGS=["-fsanitize=address,undefined"])
