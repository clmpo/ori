cd $TEMP_DIR

# newfs
echo "Creating NewFS" $TEST_FS
$ORI_EXE newfs $TEST_FS

# mount
echo "Mounting newfs"
$ORIFS_EXE $TEST_FS $TEST_FS

sleep 1

cd $TEST_FS
ls > /dev/null
cd ..

$UMOUNT $TEST_FS

cd ~/.ori/$TEST_FS.ori/
$ORIDBG_EXE verify
$ORIDBG_EXE stats
cd $TEMP_DIR

# remove
$ORI_EXE removefs $TEST_FS

