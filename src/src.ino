/*********************************************************************************
 *  MIT License
 *  
 *  Copyright (c) 2020-2023 Gregg E. Berman
 *  
 *  https://github.com/HomeSpan/HomeSpan
 *  
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *  
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *  
 ********************************************************************************/

#include "HomeSpan.h"

void setup() {
 
  Serial.begin(115200);

  homeSpan.setLogLevel(2);

  homeSpan.begin(Category::Sensors,"HomeSpan Sensors");
  
   new SpanAccessory();                       // start with Bridge Accessory
    new Service::AccessoryInformation();  
      new Characteristic::Identify(); 

   new SpanAccessory();
    new Service::AccessoryInformation();  
      new Characteristic::Identify();  
      new Characteristic::Name("Air-1");

    new Service::CarbonDioxideSensor();
      new Characteristic::CarbonDioxideDetected(Characteristic::CarbonDioxideDetected::NORMAL);
      new Characteristic::ConfiguredName("CO-1");
      new Characteristic::StatusActive(1);
      new Characteristic::StatusFault(1);
      new Characteristic::StatusTampered(1);
      new Characteristic::StatusLowBattery(0); 
      
    new Service::AirQualitySensor();
      new Characteristic::AirQuality(Characteristic::AirQuality::GOOD);
      new Characteristic::ConfiguredName("AQ-1");
      new Characteristic::StatusActive(1);
      new Characteristic::StatusFault(0);
      new Characteristic::StatusTampered(0);
      new Characteristic::StatusLowBattery(0);     

   new SpanAccessory();
    new Service::AccessoryInformation();  
      new Characteristic::Identify();  
      new Characteristic::Name("Air-2");

    new Service::AirQualitySensor();
      new Characteristic::AirQuality(Characteristic::AirQuality::EXCELLENT);
      new Characteristic::StatusActive(0);
      new Characteristic::StatusFault(1);
      new Characteristic::StatusTampered(1);
      new Characteristic::StatusLowBattery(1);

   new SpanAccessory();
    new Service::AccessoryInformation();  
      new Characteristic::Identify();  
      new Characteristic::Name("Furnace Filter");

    new Service::FilterMaintenance();
      new Characteristic::FilterChangeIndication(Characteristic::FilterChangeIndication::CHANGE_NEEDED);
      new Characteristic::FilterLifeLevel(5);
//      new Characteristic::ResetFilterIndication();


}

//////////////////////////////////////

void loop(){
 
  homeSpan.poll();
  
}
