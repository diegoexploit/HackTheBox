IFS=$'\n'
op=$(ps -eo command)

while true;do
        np=$(ps -eo command)
        diff <(echo "$op") <(echo "$np")
        sleep .2
        op=$np
done
