# 退出时不显示提示信息
set confirm off
# 不显示分页
set pagination off
# 每行打印一个结构体成员
set print pretty on
# 不显示线程启动和退出信息
set print thread-events off
# 接收到 SIGPIPE signal 时不停止
handle SIGPIPE nostop pass

# 直接启动enclave
run
continue
continue
continue
continue