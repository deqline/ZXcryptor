git checkout --orphan latest_branch
git add *
git commit -m "Cleaning"
git branch -D master
git branch -m master
git push -f origin master