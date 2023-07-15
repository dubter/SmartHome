package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const HubName = "SmartHub"

const (
	GET       = 0x00
	WHOISHERE = 0x01
	IAMHERE   = 0x02
	GETSTATUS = 0x03
	STATUS    = 0x04
	SETSTATUS = 0x05
	TICK      = 0x06
)

const (
	Hub       = 0x01
	EnvSensor = 0x02
	Switch    = 0x03
	ALL       = 0x3FFF
)

const (
	ExitCodeNoData = 0
	ExitCodeFail   = 99
)

type CustomeError struct {
	err  error
	code int
}

func (e CustomeError) Error() string {
	return fmt.Sprint("Error: ", e.err, ", Status code: ", e.code)
}

type TimerCmdBody struct {
	timeStamp uint64
}

type EnvSensorStatusCmdBody struct {
	values []uint64
}

type EnvSensorProps struct {
	sensors  byte
	triggers []struct {
		op    byte
		value uint64
		name  string
	}
}

type Trigger struct {
	on         bool   // включить устройство: on == true
	more       bool   // сравнивать по условию: больше == true
	typeSensor byte   // тип сенсора, на который срабатывает триггер (сенсор 0, 1, 2, 3 как описано выше)
	value      uint64 // это пороговое значение сенсора
	name       string // имя устройства, которое должно быть включено или выключено
}

type Device struct {
	devName  string
	devProps []byte
}

type Payload struct {
	src     uint64
	dst     uint64
	serial  uint64
	devType byte
	cmd     byte
	cmdBody []byte
}

type Packet struct {
	length  byte
	payload []byte
	crc8    byte
}

type PayloadsQueue struct {
	queue []Payload
}

func (pq *PayloadsQueue) Push(pld Payload) {
	pq.queue = append(pq.queue, pld)
}

func (pq *PayloadsQueue) Take() Payload {
	front := pq.queue[0]
	pq.queue = pq.queue[1:]
	return front
}

func (pq *PayloadsQueue) Size() int {
	return len(pq.queue)
}

type Dev struct {
	src     uint64
	devType byte
}

type SmartHub struct {
	url            string
	id             uint64
	serial         uint64
	devices        map[string]Dev    // name -> [src (14 bits), devType]
	namesDevs      map[uint64]string // src (14 bits) -> name
	switchConnDevs []string
	sensors        [4]bool // idx == номер сенсора, true - есть в наличии, false - нет.
	triggers       []Trigger
	pldsQueue      PayloadsQueue
}

func main() {
	var e CustomeError
	args := os.Args[1:]
	num, _ := strconv.ParseInt(args[1], 0, 64)
	CalculatetableCrc8()
	hub := SmartHub{url: args[0], id: uint64(num), serial: 1, devices: make(map[string]Dev), namesDevs: make(map[uint64]string)}

	err := hub.SendWhoIsHere()
	if errors.As(err, &e) {
		if e.err == nil && e.code == http.StatusNoContent {
			os.Exit(ExitCodeNoData)
		} else {
			os.Exit(ExitCodeFail)
		}
	}

	for {
		length := hub.pldsQueue.Size()
		// выполняем запланированные действия
		for i := 0; i < length; i++ {
			task := hub.pldsQueue.Take()
			err = hub.SendMess(task)
			if errors.As(err, &e) {
				if e.err == nil && e.code == http.StatusNoContent {
					os.Exit(ExitCodeNoData)
				} else {
					os.Exit(ExitCodeFail)
				}
			}
		}

		// мониторим, что пришло
		err = hub.GetMess()
		if errors.As(err, &e) {
			if e.err == nil && e.code == http.StatusNoContent {
				os.Exit(ExitCodeNoData)
			} else {
				os.Exit(ExitCodeFail)
			}
		}
	}
}

func (hub *SmartHub) Process(pld Payload, sentCmd byte) (uint64, bool, uint64) { // return time, isTICK, src
	switch pld.cmd {
	case WHOISHERE:
		hub.AddDevice(pld)
		payload := EncodePayload(Payload{src: hub.id, dst: ALL, serial: hub.serial, devType: Hub, cmd: IAMHERE, cmdBody: EncodeDevice(Device{devName: HubName})})
		packet := Packet{
			length:  byte(len(payload)),
			payload: payload,
			crc8:    ComputeCRC8(payload),
		}
		hub.serial++
		_, _ = http.Post(hub.url, "text/plain", strings.NewReader(EncodePacket(packet)))
	case IAMHERE:
		if sentCmd == WHOISHERE {
			hub.AddDevice(pld)
		}
	case STATUS:
		if _, ok := hub.namesDevs[pld.src]; ok {
			switch pld.devType {
			case Switch:
				mode := pld.cmdBody[0]
				for i := 0; i < len(hub.switchConnDevs); i++ {
					if dev, ok := hub.devices[hub.switchConnDevs[i]]; ok {
						hub.pldsQueue.Push(Payload{src: hub.id, dst: dev.src, serial: hub.serial, devType: dev.devType, cmd: SETSTATUS, cmdBody: []byte{mode}})
					}
				}
			case EnvSensor:
				hub.CheckTriggers(pld)
			}
		}
	case TICK:
		decoded := DecodeTimer(pld.cmdBody)
		return decoded.timeStamp, true, pld.src
	}
	return 0, false, pld.src
}

func (hub *SmartHub) CheckTriggers(pld Payload) {
	envSensorStatus := DecodeEnvSensorStatusCmdBody(pld.cmdBody)
	var valuesSensors [4]uint64
	// определяем какие значения к каким сенсорам относятся
	j := 0
	for i := range hub.sensors {
		if hub.sensors[i] {
			valuesSensors[i] = envSensorStatus.values[j]
			j++
		}
	}

	for _, trigger := range hub.triggers {
		mode := byte(0)
		if trigger.on {
			mode = 1
		}
		if _, ok := hub.devices[trigger.name]; ok && hub.sensors[trigger.typeSensor] {
			if trigger.more && valuesSensors[trigger.typeSensor] > trigger.value || !trigger.more && valuesSensors[trigger.typeSensor] < trigger.value {
				hub.pldsQueue.Push(Payload{src: hub.id, dst: hub.devices[trigger.name].src, serial: hub.serial, devType: hub.devices[trigger.name].devType, cmd: SETSTATUS, cmdBody: []byte{mode}})
			}
		}
	}
}

func (hub *SmartHub) AddDevice(pld Payload) {
	decoded := DecodeDevice(pld.cmdBody)
	hub.devices[decoded.devName] = Dev{src: pld.src, devType: pld.devType}
	hub.namesDevs[pld.src] = decoded.devName
	switch pld.devType {
	case Switch:
		hub.switchConnDevs = DecodeSwitchProps(decoded.devProps)
		hub.pldsQueue.Push(Payload{src: hub.id, dst: pld.src, serial: hub.serial, devType: Switch, cmd: GETSTATUS})
	case EnvSensor:
		envSensor := DecodeEnvSensorProps(decoded.devProps)
		// sensors
		hub.sensors[0] = envSensor.sensors&0x1 != 0 // имеется датчик температуры (сенсор 0)
		hub.sensors[1] = envSensor.sensors&0x2 != 0 // имеется датчик влажности (сенсор 1)
		hub.sensors[2] = envSensor.sensors&0x4 != 0 // имеется датчик освещенности (сенсор 2)
		hub.sensors[3] = envSensor.sensors&0x8 != 0 // имеется датчик загрязнения воздуха (сенсор 3)

		// triggers
		hub.triggers = make([]Trigger, len(envSensor.triggers))
		for i := 0; i < len(envSensor.triggers); i++ {
			hub.triggers[i].on, hub.triggers[i].more, hub.triggers[i].typeSensor = parseByteFlags(envSensor.triggers[i].op)
			hub.triggers[i].value = envSensor.triggers[i].value
			hub.triggers[i].name = envSensor.triggers[i].name
		}
		hub.pldsQueue.Push(Payload{src: hub.id, dst: pld.src, serial: hub.serial, devType: EnvSensor, cmd: GETSTATUS})
	}
}

func (hub *SmartHub) SendWhoIsHere() error {
	device := EncodeDevice(Device{devName: HubName})
	payload := Payload{src: hub.id, dst: ALL, serial: hub.serial, devType: Hub, cmd: WHOISHERE, cmdBody: device}
	return hub.SendMess(payload)
}

func (hub *SmartHub) SendMess(pld Payload) error {
	bytesPld := EncodePayload(pld)
	hasAnswer := pld.dst == ALL
	var firstTime uint64
	packet := Packet{
		length:  byte(len(bytesPld)),
		payload: bytesPld,
		crc8:    ComputeCRC8(bytesPld),
	}
	hub.serial++

	ok, err := hub.PostWithTimeOut(EncodePacket(packet), pld.dst, pld.cmd, &hasAnswer, &firstTime)
	// пустыми запросами читаем ответ до 300 мс
	for ok {
		ok, err = hub.PostWithTimeOut("", pld.dst, pld.cmd, &hasAnswer, &firstTime)
	}
	return err
}

func (hub *SmartHub) GetMess() error {
	resp, err := http.Post(hub.url, "text/plain", strings.NewReader(""))
	if err != nil || (resp.StatusCode != http.StatusOK) {
		return CustomeError{err, resp.StatusCode}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Распаковка пакетов
	pkts := DecodePackets(string(body))
	plds := DecodePayloads(pkts)
	for i := 0; i < len(plds); i++ {
		_, _, _ = hub.Process(plds[i], GET)
	}
	return nil
}

func (hub *SmartHub) PostWithTimeOut(strBase64 string, to uint64, sentCmd byte, hasAnswer *bool, firstTime *uint64) (bool, error) {
	resp, err := http.Post(hub.url, "text/plain", strings.NewReader(strBase64))
	if err != nil || (resp.StatusCode != http.StatusOK) {
		return false, CustomeError{err, resp.StatusCode}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Распаковка пакетов
	pkts := DecodePackets(string(body))
	plds := DecodePayloads(pkts)
	for i := 0; i < len(plds); i++ {
		time, ok, src := hub.Process(plds[i], sentCmd)
		if src == to {
			*hasAnswer = true
		}
		if *firstTime == 0 && ok { // firstTime здесь как флаг работает
			*firstTime = time
		}

		if ok && time-*firstTime >= 300 {
			if !(*hasAnswer) {
				delete(hub.devices, hub.namesDevs[to])
				delete(hub.namesDevs, to)
			}
			return false, nil
		}
	}
	return true, nil
}

func DecodeEnvSensorStatusCmdBody(bts []byte) EnvSensorStatusCmdBody {
	var envSensorStatus EnvSensorStatusCmdBody
	b := bytes.NewReader(bts)
	length, _ := b.ReadByte()
	envSensorStatus.values = make([]uint64, length)
	for i := 0; i < int(length); i++ {
		envSensorStatus.values[i] = readVarUint(b)
	}
	return envSensorStatus
}

func DecodeEnvSensorProps(bts []byte) EnvSensorProps {
	b := bytes.NewReader(bts)
	var envSensor EnvSensorProps
	envSensor.sensors, _ = b.ReadByte()
	length, _ := b.ReadByte()
	envSensor.triggers = make([]struct {
		op    byte
		value uint64
		name  string
	}, length)
	for i := 0; i < int(length); i++ {
		envSensor.triggers[i].op, _ = b.ReadByte()
		envSensor.triggers[i].value = readVarUint(b)
		lenStr, _ := b.ReadByte()
		str := make([]byte, lenStr)
		for j := 0; j < int(lenStr); j++ {
			str[j], _ = b.ReadByte()
		}
		envSensor.triggers[i].name = string(str)
	}
	return envSensor
}

func DecodeSwitchProps(bts []byte) []string {
	b := bytes.NewReader(bts)
	ans := make([]string, 0)
	_, _ = b.ReadByte()
	for b.Len() > 0 {
		length, _ := b.ReadByte()
		str := make([]byte, length)
		for i := 0; i < int(length); i++ {
			str[i], _ = b.ReadByte()
		}
		ans = append(ans, string(str))
	}
	return ans
}

func DecodeDevice(b []byte) Device {
	var device Device
	if len(b) > 0 {
		length := int(b[0])
		device.devName = string(b[1 : length+1])
		device.devProps = b[length+1:]
		return device
	}
	return Device{}
}

func DecodeTimer(bts []byte) TimerCmdBody {
	var timer TimerCmdBody
	b := bytes.NewReader(bts)
	timer.timeStamp = readVarUint(b)
	return timer
}

func DecodePackets(str string) []Packet {
	ans := make([]Packet, 0)
	mess, err := base64.RawURLEncoding.DecodeString(IgnoreExcessSymbols(str))
	if err != nil {
		return []Packet{}
	}
	b := bytes.NewReader(mess)
	for b.Len() > 0 {
		var pkt Packet
		pkt.length, _ = b.ReadByte()
		for i := 0; i < int(pkt.length); i++ {
			readByte, _ := b.ReadByte()
			pkt.payload = append(pkt.payload, readByte)
		}
		pkt.crc8, _ = b.ReadByte()
		if ComputeCRC8(pkt.payload) == pkt.crc8 {
			ans = append(ans, pkt)
		}
	}
	return ans
}

func DecodePayloads(pkts []Packet) []Payload {
	ans := make([]Payload, 0)
	for i := 0; i < len(pkts); i++ {
		var pld Payload
		b := bytes.NewReader(pkts[i].payload)
		pld.src = readVarUint(b)
		pld.dst = readVarUint(b)
		pld.serial = readVarUint(b)
		pld.devType, _ = b.ReadByte()
		pld.cmd, _ = b.ReadByte()
		for b.Len() > 0 {
			k, _ := b.ReadByte()
			pld.cmdBody = append(pld.cmdBody, k)
		}
		ans = append(ans, pld)
	}
	return ans
}

func EncodePacket(pkt Packet) string {
	var mess []byte
	mess = append(mess, pkt.length)
	mess = append(mess, pkt.payload...)
	mess = append(mess, pkt.crc8)
	return base64.RawURLEncoding.EncodeToString(mess)
}

func EncodePayload(p Payload) []byte {
	mess := make([]byte, 0)
	mess = append(mess, encodeULEB128(p.src)...)
	mess = append(mess, encodeULEB128(p.dst)...)
	mess = append(mess, encodeULEB128(p.serial)...)
	mess = append(mess, p.devType)
	mess = append(mess, p.cmd)
	mess = append(mess, p.cmdBody...)
	return mess
}

func readVarUint(b *bytes.Reader) uint64 {
	var result uint64
	var shift uint
	for {
		byteVal, _ := b.ReadByte()
		result |= uint64(byteVal&0x7F) << shift
		if byteVal&0x80 == 0 {
			break
		}
		shift += 7
	}
	return result
}

func EncodeDevice(device Device) []byte {
	ans := make([]byte, 0)
	ans = append(ans, byte(len(device.devName)))
	ans = append(ans, []byte(device.devName)...)
	ans = append(ans, device.devProps...)
	return ans
}

func encodeULEB128(n uint64) []byte {
	var result []byte
	for {
		// Получаем 7 младших битов числа
		b := byte(n & 0x7F)
		// Сдвигаем число на 7 бит вправо
		n >>= 7
		// Если есть еще биты, устанавливаем старший бит в 1
		if n != 0 {
			b |= 0x80
		}
		// Добавляем байт в результат
		result = append(result, b)
		// Если все биты обработаны, выходим из цикла
		if n == 0 {
			break
		}
	}
	return result
}

func ComputeCRC8(bytes []byte) byte {
	crc := byte(0)
	for _, b := range bytes {
		data := b ^ crc
		crc = crctable[data]
	}

	return crc
}

var crctable = make([]byte, 256)
var generator byte = 0x1D

func CalculatetableCrc8() {
	for dividend := 0; dividend < 256; dividend++ {
		currByte := byte(dividend)

		for bit := 0; bit < 8; bit++ {
			if (currByte & 0x80) != 0 {
				currByte <<= 1
				currByte ^= generator
			} else {
				currByte <<= 1
			}
		}

		crctable[dividend] = currByte
	}
}

func IgnoreExcessSymbols(str string) string {
	// создаем функцию-предикат для фильтрации символов
	filter := func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n'
	}
	// фильтруем символы
	newStr := strings.Map(func(r rune) rune {
		if filter(r) {
			return -1 // удаление символа
		}
		return r // оставляем символ
	}, str)
	return newStr
}

func parseByteFlags(flags byte) (bool, bool, byte) {
	isOn := flags&0x1 != 0
	isGreaterThan := flags&0x2 != 0
	sensorType := flags >> 2 & 0x3
	return isOn, isGreaterThan, sensorType
}
