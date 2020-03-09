#echo "# Burp" >> README.md
git init
#git add README.md
git commit -m '19.13 修复读取poc yaml bug,并添加各个命令的测试' -a
git remote add origin git@github.com:Supertao/Burp.git
git push -u origin master
