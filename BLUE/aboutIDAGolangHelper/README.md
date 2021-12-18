最近使用[IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)进行二进制文件分析时，发现对于Go 1.16打包的二进制文件的函数重命名会报错。最终排查是字符串处理的问题，发生在`\GO_Utils\Types.py`中，经过了一些小位置的改动，替换后可用，并且由于其中一个变量的原因，在点击 **Rename Functions** 前，需要先点击 **Try to detemine go version based on moduledata**。

最后要说的是，目前只是试过了Windows平台的几个64位Go 1.16版本二进制文件（还是在日常工作中碰到的），虽然可用，但是由于没有特别细地研究过Go的打包格式，所以不确定有没有其他问题。比如处理低于1.16版本或许有需要切回原版了，还有其它平台的文件处理格式等。这里只是提供一个有点繁琐，但是省事的办法。
