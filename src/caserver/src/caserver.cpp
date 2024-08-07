// caserver.cpp : Defines the entry point for the application.
//

#include "caserver.h"
#include "crypto/provider.h"

using namespace std;

int main()
{
	ENGINE* engine = ENGINE_by_id("gost");

	Provider provider{engine};
	auto kp = provider.GenerateKeyPair();

	cout << "Hello CMake." << endl;
	return 0;
}
