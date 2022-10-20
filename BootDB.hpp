/*
This is a basic fast database header for the DecentMC protocol.
In the future it my be replaced with a sqlite3 or whatever. I dont have time to learn a new API.
Or another will be build on top of it. Maybe use vector of BOOTDB_BLOCK_SIZE to create a whole filesystem for variable length blocks. I dont foresee needing to
store more then 512 bytes of the protocol per record.
*/

#ifndef __DECENT_MC_BOOTDB__
#define __DECENT_MC_BOOTDB__

#include <cstdio>
#include <iostream>
#include <string>
#include <memory>
#include <cstring>
#include <fstream>
#include <chrono>
#include <random>

// BOOTDB parameters
#define BOOTDB_BLOCK_SIZE 512
#define BOOTDB_HEADER_SIZE sizeof(BootDB::DatabaseHeader)

namespace BootDB
{
    uint64_t GetTime()
    {
        return (uint64_t)(std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count());
    }
    std::string create_rand_bytes(int size)
    {
        std::string pt;
        std::mt19937_64 gen(GetTime());
        for (int i = 0; i < size; i++)
        {
            pt = pt + (char)((gen()) % 256);
        }
        return pt;
    }
    struct DatabaseHeader
    {
        const char magic_bytes[4] = {0x38, 0x53, 0x3f, 0x4f}; //  May change for production.
        const uint8_t version_id = 0x01;
        uint64_t time_created;
        unsigned char owner_id[32];                  /// UUID of owning node
        unsigned char ed25519_signature_of_file[64]; // Uses ED25519 openssl implementation.
        unsigned char reserved[512];                 // May use later.
    };
    enum RecordType // All records have a size of BOOTDB_BLOCK_SIZE variable. This is specific for the DecentMC protocol
    {
        MasterPrivateKey = 0, // Block 0
        MasterPublicKey,
        IsVerifiedNode,
        NodeInfo,
        HostInfo,
        KeyStore,
        SessionKey,
        NodeId,
        R1, // Database registers for storing arbitary fixed length data. No larger then BOOTDB_BLOCK_SIZE.
        R2,
        R3,
        R4,
        R5,
        R6
    }; // Undefined RecordTypes will still be valid.
    class LocalDatabase
    {
    public:
        // Singleton class
        static LocalDatabase *getInstance()
        {
            if (instance == 0)
            {
                instance = new LocalDatabase();
            }
            return instance;
        }
        // Init and write header
        static bool Init(std::string filepath)
        {
            FilePath = filepath;
            if (!Open())
            {
                return false;
            }

            if (!IsValid())
            {
                if (!WriteDatabaseHeader())
                {
                    return false;
                }
            }
            if (!IsValid())
            {
                Clear();
            }
            return true;
        }
        static int Close()
        {
            _database->close();
            return 0;
        }
        static bool Open()
        {
            if (_database->is_open())
            {
                _database->close();
            }
            std::fstream fs;
            fs.open(FilePath, std::ios::out | std::ios::app);
            fs.close();
            _database->open(FilePath, std::ios_base::binary | std::ios_base::in | std::ios_base::out);
            if (!(_database->is_open()))
            {
                return false;
            }
            return true;
        }
        static bool IsOpen()
        {
            return _database->is_open();
        }
        // Get size in byts if database including header
        static long Size()
        {
            size_t size = 0;
            int tmp = GetPos();
            _database->seekg(0, std::ios::end);
            _database->seekp(0, std::ios::end);
            size = GetPos();
            SetPos(tmp);
            return size;
        }
        // Check if database is empty and has not been written to.
        static bool IsFresh()
        {
            if (Size() == BOOTDB_HEADER_SIZE)
            {
                return true;
            }
            return false;
        }
        // Read record. Reads std::string of length == BOOTDB_BLOCK_SIZE
        static std::string ReadRecord(RecordType type)
        {
            return ReadRecord(type, BOOTDB_BLOCK_SIZE);
        }
        // Reads record of specified length. prefered
        static std::string ReadRecord(RecordType type, int expected_length)
        {
            char buf[expected_length];

            int tmp = GetPos();
            int pos = BOOTDB_HEADER_SIZE + (BOOTDB_BLOCK_SIZE * type);
            if (Size() < pos)
            {
                std::string result;
                ;
                return result;
            }
            SetPos(pos);
            _database->read(buf, expected_length);
            SetPos(tmp);
            std::string result = std::string(buf, expected_length);
            return result;
        }
        // write record
        static bool WriteRecord(RecordType type, std::string data)
        {
            if (!IsOpen())
            {
                return false;
            }
            if (data.length() > BOOTDB_BLOCK_SIZE)
            {
                return false;
            }
            int size = Size();
            int pos = BOOTDB_HEADER_SIZE + (BOOTDB_BLOCK_SIZE * type);

            if (pos > size)
            {
                int needed_len = pos - size;
                char buf[needed_len];
                memset(buf, 0, needed_len);
                Write(size, buf, needed_len);
            }
            char block[BOOTDB_BLOCK_SIZE];
            memset(block, 0, BOOTDB_BLOCK_SIZE);
            memcpy(block, data.data(), data.length());
            Write(pos, block, BOOTDB_BLOCK_SIZE);
            return true;
        }
        // Clear all data in database and reset size. Re-initilizes database header. (With new id)
        static void Clear()
        {
            _database->close();
            std::ofstream ofs(FilePath, std::ofstream::out | std::ofstream::trunc);
            ofs.close();
            Open();
            WriteDatabaseHeader();
            return;
        }
        // Mind that this could cause seg faults
        ~LocalDatabase()
        {
            delete _database;
        }

    private:
        static LocalDatabase *instance;
        static std::fstream *_database;
        static std::string FilePath;
        LocalDatabase()
        {
        } // Size of struct is 632 bytes
        static void SetPos(int pos)
        {
            _database->seekg(pos);
            _database->seekp(pos);
        }
        static int GetPos()
        {
            int tg = _database->tellg();
            int tp = _database->tellp();
            if (tg == tp)
            {
                return tg;
            }
            return tg; // Hope this doesn't come back to bite me.
        }
        // Low level write
        static void Write(int pos, const char *buf, int size)
        {
            int tmp = GetPos();
            SetPos(pos);
            _database->write(buf, size);
            SetPos(tmp);
            return;
        }
        // Check if database is valid. Based on length and magic bytes.
        static bool IsValid()
        {
            if (Size() < 4)
            {
                return false;
            }
            int tmp = GetPos();
            SetPos(0);
            char buf[4];
            _database->read(buf, 4);
            SetPos(tmp);
            char magic_bytes[4] = {0x38, 0x53, 0x3f, 0x4f};
            if (memcmp(buf, magic_bytes, 4) != 0)
            {
                return false;
            }
            if (((Size() - BOOTDB_HEADER_SIZE) % BOOTDB_BLOCK_SIZE) != 0)
            {
                return false;
            }
            return true;
        }
        // Writes database header with new random ID.
        static bool WriteDatabaseHeader()
        {
            struct DatabaseHeader dbh = DatabaseHeader();
            uint64_t time = GetTime();
            dbh.time_created = time;
            strcpy((char *)dbh.owner_id, create_rand_bytes(32).c_str());
            SetPos(0);
            Write(0, (const char *)&dbh, sizeof(dbh));
            return true;
        }
    };
    LocalDatabase *LocalDatabase::instance = 0;
    std::fstream *LocalDatabase::_database = new std::fstream();
    std::string LocalDatabase::FilePath = "";
}

#endif