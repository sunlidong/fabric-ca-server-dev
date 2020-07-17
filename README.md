# fabric-ca-server-dev


################################################################

    1. go build .
    2. go mod vendor 
    3. go tify



################################################################

- 用 go get -u 更新现有的依赖
- 用 go mod download 下载 go.mod 文件中指明的所有依赖
- 用 go mod tidy 整理现有的依赖
- 用 go mod graph 查看现有的依赖结构
- 用 go mod init 生成 go.mod 文件 (Go 1.13 中唯一一个可以生成 go.mod 文件的子命令)
- 用 go get -u 更新现有的依赖
- 用 go mod download 下载 go.mod 文件中指明的所有依赖
- 用 go mod tidy 整理现有的依赖
- 用 go mod graph 查看现有的依赖结构
- 用 go mod init 生成 go.mod 文件 (Go 1.13 中唯一一个可以生成 go.mod 文件的子命令)
- 用 go mod edit 编辑 go.mod 文件
- 用 go mod vendor 导出现有的所有依赖 (事实上 Go modules 正在淡化 Vendor 的概念)
- 用 go mod verify 校验一个模块是否被篡改过