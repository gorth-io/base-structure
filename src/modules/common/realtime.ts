// export function createCommonRealtimeUtils(client: SupabaseAnyClient): RealtimeUtils {
//   return {
//     createChannel(topic: string, options?: RealtimeChannelOptions) {
//       return client.channel(topic, options)
//     },
//     subscribe(
//       channel: RealtimeChannel,
//       callback?: (status: REALTIME_SUBSCRIBE_STATES, error?: Error) => void
//     ) {
//       return new Promise<REALTIME_SUBSCRIBE_STATES>((resolve, reject) => {
//         channel.subscribe((status, error) => {
//           callback?.(status, error)
//
//           if (error) {
//             reject(error)
//             return
//           }
//
//           if (
//             status === 'SUBSCRIBED' ||
//             status === 'CHANNEL_ERROR' ||
//             status === 'TIMED_OUT' ||
//             status === 'CLOSED'
//           ) {
//             resolve(status)
//           }
//         })
//       })
//     },
//     // removeChannel(channel: RealtimeChannel) {
//     //   return client.removeChannel(channel)
//     // },
//     // removeAllChannels() {
//     //   return client.removeAllChannels()
//     // },
//   }
// }

export type { RealtimeUtils } from "@/utils/interface";
