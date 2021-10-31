#!/bin/bash
if [ $USER != "student" ]; then
  echo "Please run as student."
  exit
fi

read -p "--- Assume your remote repo is empty. Delete .git folder if this is a re-initialization? (y/n)" choice0

if [ "$choice0" == "y" ]; then
rm -rf ./.git
fi

read -p "--- Assume your VM's git has access to your GitHub account, and you have configured your name and email for git. Continue? (y/n)" choice

if [ -z "$choice" ] || [ "$choice" != "y" ]; then
exit
fi

git init
git add .
git commit -m "first commit"
git branch -M main

read -p '--- Input SSH URL to your Github repo (git@...): ' repo_url
git remote add origin $repo_url

echo "--- Push to remote"
git push -u origin main

echo "--- Done."

