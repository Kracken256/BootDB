#include "BootDB.hpp"

using namespace BootDB;

static uint64_t GetTime()
{
    return (uint64_t)(std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count());
}

static std::string create_rand_bytes(int size)
{
    std::string pt;
    std::mt19937_64 gen = std::mt19937_64(GetTime());
    for (int i = 0; i < size; i++)
    {
        pt = pt + (char)((gen()) % 256);
    }
    return pt;
}

int main()
{
    LocalDatabase *db = LocalDatabase::getInstance();
    db->Init("database.bootdb");
    db->Clear();
    db->WriteRecord(RecordType::MasterPrivateKey, create_rand_bytes(32));
    db->Close();
    return 0;
}