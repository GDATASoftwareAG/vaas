find . -name composer.json -not -path */vendor/* | while read composer; do
    dir=$(dirname $composer)
    echo "Updating $dir"
    composer --working-dir=$dir update
done