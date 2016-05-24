```
Author:WinterSun
date:2016年5月11日 11:17:30
PS:为了更好的方便以后查看赛题（主要是碰到类似的，可以直接拿来参考）
```
参考资料:[http://blog.csdn.net/waitfor_/article/details/23466607](http://blog.csdn.net/waitfor_/article/details/23466607)
[https://help.github.com/articles/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent/#platform-linux](https://help.github.com/articles/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent/#platform-linux)
[https://help.github.com/articles/adding-a-new-ssh-key-to-your-github-account/](https://help.github.com/articles/adding-a-new-ssh-key-to-your-github-account/)

打开linux终端。
生成一个新的ssh私钥。`ssh-keygen -t rsa -b 4096 -C "your_email@example.com"`
全部选择默认，一路回车即可。

会在/root/.ssh/目录下生成两个文件，一个公钥一个私钥。
```
root@kali:~/Desktop/ctf_task# ls /root/.ssh/ -al
总用量 24
drwx------  2 root root 4096  4月 19 08:41 .
drwxr-xr-x 46 root root 4096  5月 11 11:05 ..
-rw-------  1 root root 1679  4月 19 08:41 id_rsa
-rw-r--r--  1 root root  398  4月 19 08:41 id_rsa.pub
-rw-r--r--  1 root root 5534  4月 19 08:57 known_hosts
```
我们需要将我们的公钥文件放入到我们的github账户中去。
`cat /root/.ssh/id_rsa.pub`

进入个人设置。将我们的公钥加进去。
然后配置用户名和e-mail
```
git config --global user.name "your name"      //配置用户名
git config --global user.email "your email"    //配置email 
```
设置好之后
进入目标文件夹，然后`git init`，对该文件夹进行版本控制。

关键语句`git remote add origin git@github.com:Winter3un/ctf_task.git`

为用户名为`Winter3un`的`github`账户创建一个名字为`ctf_task`远程仓库(这个仓库应当已经登录github网站并创建好。)

```
git init #初始化一个本地库
git add -A #添加所有修改到本地仓库
git commit -m "first commit" #提交到本地库并备注，此时变更仍在本地。
git remote add orgin git@github.com:xxx/xxx.git  #增加一个远程服务器的别名。
git push -u orgin master #将本地文件提交到Github的remoname版本库中。此时才更新了本地变更到github服务上。
```

