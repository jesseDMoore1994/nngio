// Updated header file: libnngio_management.h

#ifndef LIBNNGIO_MANAGEMENT_H
#define LIBNNGIO_MANAGEMENT_H

// Includes
#include <protobuf/transport_service.h>
#include <protobuf/connection_service.h>
#include <protobuf/protocol_service.h>
#include <protobuf/management_service.h>

// Transport Service
namespace TransportService {
    void sendData(const Data& data);
    Data receiveData();
}

// Connection Service
namespace ConnectionService {
    void establishConnection(const ConnectionParams& params);
    void closeConnection();
}

// Protocol Service
namespace ProtocolService {
    void initiateProtocol(const ProtocolParams& params);
    void terminateProtocol();
}

// Management Service
namespace ManagementService {
    void manageResources();
    void monitorPerformance();
}

#endif // LIBNNGIO_MANAGEMENT_H